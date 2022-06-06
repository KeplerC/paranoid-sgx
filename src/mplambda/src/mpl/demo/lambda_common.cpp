#include <mpl/demo/app_options.hpp>
#include <mpl/demo/se3_rigid_body_scenario.hpp>
#include <mpl/demo/fetch_scenario.hpp>
#include <mpl/prrt.hpp>
#include <mpl/comm.hpp>
#include <mpl/pcforest.hpp>
#include <mpl/option.hpp>
#include <getopt.h>
#include <optional>
#include <capsule.h>

// these static variables are needed by Anna
namespace mpl::demo {

    template <class T, class U>
    struct ConvertState : std::false_type {};

    template <class R, class S>
    struct ConvertState<
        std::tuple<Eigen::Quaternion<R>, Eigen::Matrix<R, 3, 1>>,
        std::tuple<Eigen::Quaternion<S>, Eigen::Matrix<S, 3, 1>>>
        : std::true_type
    {
        using Result = std::tuple<Eigen::Quaternion<R>, Eigen::Matrix<R, 3, 1>>;
        using Source = std::tuple<Eigen::Quaternion<S>, Eigen::Matrix<S, 3, 1>>;
        
        static Result apply(const Source& q) {
            return Result(
                std::get<0>(q).template cast<R>(),
                std::get<1>(q).template cast<R>());
        }
    };

    template <class R, class S, int dim>
    struct ConvertState<Eigen::Matrix<R, dim, 1>, Eigen::Matrix<S, dim, 1>>
        : std::true_type
    {
        using Result = Eigen::Matrix<R, dim, 1>;
        using Source = Eigen::Matrix<S, dim, 1>;

        static Result apply(const Source& q) {
            return q.template cast<R>();
        }
    };

    template <class T, class Rep, class Period>
    void sendPath(
        asylo::KVSClient *KVS_client, const std::string& solutionPathKey,
        std::chrono::duration<Rep, Period> elapsed, T& solution)
    {
        // unsigned long int now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();

        using State = typename T::State;
        using Distance = typename T::Distance;
        
        std::vector<State> path;
        solution.visit([&] (const State& q) { path.push_back(q); });
        std::reverse(path.begin(), path.end());
        
        Distance cost = solution.cost();
        // comm.sendPath(cost, elapsed, std::move(path));
        std::uint32_t elapsedMillis = std::chrono::duration_cast<std::chrono::milliseconds>(
            elapsed).count();
        packet::Path<State> packet(cost, elapsedMillis, std::move(path));
        Buffer buf = packet;
        std::string k = solutionPathKey;

        LOG(INFO) << "In sendPath: with cost: " << (cost);
        // std::cout << "Serialized Path: " << buf.getString() << std::endl;

        // PriorityLattice<double, string> val(PriorityValuePair<double, string>(cost, buf.getString()));
        KVS_client->put(k, buf.getString(), "MPL");
    }


    template <class T, class Rep, class Period>
    void sendPath(Comm& comm, std::chrono::duration<Rep, Period> elapsed, T& solution) {
        using State = typename T::State;
        using Distance = typename T::Distance;
        if (comm) {
            std::vector<State> path;
            solution.visit([&] (const State& q) { path.push_back(q); });
            std::reverse(path.begin(), path.end());
            Distance cost = solution.cost();
            comm.sendPath(cost, elapsed, std::move(path));
        }
    }

    template <class Scenario, class Algorithm, class ... Args>
    void runPlanner(const demo::AppOptions& options, Args&& ... args) {
        using State = typename Scenario::State;
        using Distance = typename Scenario::Distance;

        State qStart = options.start<State>();


        // std::vector<UserRoutingThread> threads;
        // Address addr("127.0.0.1");
        // threads.push_back(UserRoutingThread(addr, 0));
        // Address ip("127.0.0.1");

        asylo::KVSClient *kvsClient = options.KVSClient(); 

	    // int thread_id = options.thread_id_;
        // KvsClient kvsClient(threads, ip, thread_id, 10000);
        // Comm comm_;

        if (options.coordinator(false).empty()) {
            JI_LOG(WARN) << "no coordinator set";
        // } else {
        //     comm_.setProblemId(options.problemId());
        //     comm_.connect(options.coordinator());
        }

        JI_LOG(INFO) << "setting up planner";
        Planner<Scenario, Algorithm> planner(std::forward<Args>(args)...);

        JI_LOG(INFO) << "Adding start state: " << qStart;
        planner.addStart(qStart);

        JI_LOG(INFO) << "Starting solve()";
        using Clock = std::chrono::steady_clock;
        Clock::duration maxElapsedSolveTime = std::chrono::duration_cast<Clock::duration>(
            std::chrono::duration<double>(options.timeLimit()));
        auto start = Clock::now();

        // record the initial solution (it should not be an actual
        // solution).  We use this later to perform the C-FOREST path
        // update, and to check if we should write out one last
        // solution.
        auto solution = planner.solution();
        assert(!solution);

        const std::string solutionPathKey = "solution_path";
        //kvsClient.get_async(solutionPathKey);

        if constexpr (Algorithm::asymptotically_optimal) {                
            // asymptotically-optimal planner, run for the
            // time-limit, and update the graph with best paths
            // from the network.
            planner.solve([&] {

                if (maxElapsedSolveTime.count() > 0 && Clock::now() - start > maxElapsedSolveTime)
                    return true;

	            kvs_payload dc_sol_path =  kvsClient->get(solutionPathKey);
                // std::vector<KeyResponse> responses = kvsClient->get(solutionPathKey);

                if (!dc_sol_path.key.empty()) {
                    
		    // PriorityLattice<double, string> pri_lattice =
		    //     deserialize_priority(responses[0].tuples(0).payload());
            
            
            // Buffer buf(pri_lattice.reveal().value);
            Buffer buf(dc_sol_path.value);
		    // string str = static_cast<std::string>(buf);


		    //if (!str.empty()) JI_LOG(INFO) << "responses " <<  str;
			//if (responses[0].tuples()[0].error() == AnnaError::NO_ERROR) {
			//	JI_LOG(INFO) << "Success!" ;
			//} else {
			//	JI_LOG(INFO) << "Failure! " << responses[0].tuples()[0].error() ;
			//}

		    //if (!buf.getString().empty()) JI_LOG(INFO) << "responses " << pri_lattice.reveal().value;
		    // if (!buf.getString().empty()) 
            // JI_LOG(INFO) << "responses " << buf.getString();

                    // process the payload, note: packet::parse will
                    // not do anything if the buffer is empty.

                    packet::parse(
                        buf,
                        [&] (auto&& path) {
                            if constexpr (std::is_same_v<std::decay_t<decltype(path)>, packet::Path<State>>) {
                                // do not update our solution if we
                                // already have the a solution with
                                // the same or better cost.
                                if (solution.cost() <= path.cost())
                                    return;

                                unsigned long int now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                                JI_LOG(INFO) << "Solution cost: " <<  path.cost() << " Duration to find solution: " << (now - options.timeStart); 

                                planner.addPath(path.cost(), path.path());

                                // update our best solution if it has
                                // the same cost as the solution we
                                // just got from a peer.  If we have a
                                // different solution, then we'll
                                // update and send the solution after
                                // the comm_.process().  This avoids
                                // re-broadcasting the same solution.
                                // (It is possible that incorporating
                                // the new solution will lower the
                                // cost)
                                auto newSol = planner.solution();
				
                                if (newSol.cost() == path.cost())
                                    solution = newSol;
                            } else {
                                JI_LOG(WARN) << "received invalid path type!";
                            }
                        });
                }
                
                auto s = planner.solution();
                // JI_LOG(INFO) << "s.cost(): " << s.cost();
		        // JI_LOG(INFO) << "using planner: " << s.cost() << solution.cost();
                if (s < solution) {
                    unsigned long int now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                    JI_LOG(INFO) << " duration: " << (now - options.timeStart);
                    // sendPath(comm_, Clock::now() - start, s);
                    sendPath(kvsClient, solutionPathKey, Clock::now() - start, s);
                    solution = s;
                }
                
                // return comm_.isDone();
                return false;
            });
        } else {
            // non-asymptotically-optimal.  Stop as soon as we
            // have a solution (either locally or from the
            // network)
            bool hasPath = false;
            planner.solve([&] {
                if (maxElapsedSolveTime.count() > 0 && Clock::now() - start > maxElapsedSolveTime)
                    return true;

                if (!hasPath) {
                    kvs_payload dc_sol_path = kvsClient->get(solutionPathKey);
                    if (dc_sol_path.key.empty()) {
                        // TODO: check if there's a path, if so, we're done
                        // hasPath = true;
                        dc_sol_path = kvsClient->get(solutionPathKey);
                    }
              
                    // std::vector<KeyResponse> responses = kvsClient->get(solutionPathKey);
                    // if (!responses.empty()) {
                    //     // TODO: check if there's a path, if so, we're done
                    //     // hasPath = true;
                    //     kvsClient->get(solutionPathKey);
                    // }
                }

                return hasPath || planner.isSolved();
            });
        }
            
        
        JI_LOG(INFO) << "solution " << (planner.isSolved() ? "" : "not ") << "found after " << (Clock::now() - start);
        JI_LOG(INFO) << "graph size = " << planner.size();
        JI_LOG(INFO) << "cost " << planner.solution().cost(); 
        JI_LOG(INFO) << "samples (goal-biased, rejected) = " << planner.samplesConsidered() << " ("
                     << planner.goalBiasedSamples() << ", "
                     << planner.rejectedSamples() << ")";
            
        if (auto finalSolution = planner.solution()) {
            if (finalSolution != solution)
                sendPath(kvsClient, solutionPathKey, Clock::now() - start, finalSolution);
                // sendPath(comm_, Clock::now() - start, finalSolution);
            finalSolution.visit([] (const State& q) { JI_LOG(INFO) << "  " << q; });
        }

#if 0   // write the end-effector vertices to stdout
        if constexpr (std::is_same_v<State, Eigen::Matrix<double, 8, 1>>) {
            // std::map<const State*, std::size_t> stateIndex;
            planner.visitTree([&] (const State& a, const State& b) {
                demo::FetchRobot<double> robot(a);
                Eigen::IOFormat fmt(Eigen::StreamPrecision, Eigen::DontAlignCols, " ", " ");
                std::cout << "v " << robot.getEndEffectorFrame().translation().format(fmt) << std::endl;
                // stateIndex.emplace(&a, stateIndex.size() + 1);
            });
            // planner.visitTree([&] (const State& a, const State& b) {
            //     auto ait = stateIndex.find(&a);
            //     auto bit = stateIndex.find(&b);
            //     std::cout << "l " << ait->second << " " << bit->second << " " << ait->second << std::endl;
            // });
        }
#endif

        // comm_.sendDone();
        // TODO: we need to send something
    }


    template <class Algorithm, class S>
    void runSelectScenario(const demo::AppOptions& options) {
        JI_LOG(INFO) << "running scenario: " << options.scenario();
        if (options.scenario() == "se3") {
            using Scenario = mpl::demo::SE3RigidBodyScenario<S>;
            using Bound = typename Scenario::Bound;
            using State = typename Scenario::State;
            State goal = options.goal<State>();
            Bound min = options.min<Bound>();
            Bound max = options.max<Bound>();
            runPlanner<Scenario, Algorithm>(
                options, options.env(), options.robot(), goal, min, max,
                options.checkResolution(0.1));
        } else if (options.scenario() == "fetch") {
            using Scenario = mpl::demo::FetchScenario<S>;
            using State = typename Scenario::State;
            using Frame = typename Scenario::Frame;
            using GoalRadius = Eigen::Matrix<S, 6, 1>;
            Frame envFrame = options.envFrame<Frame>();
            Frame goal = options.goal<Frame>();
            GoalRadius goalRadius = options.goalRadius<GoalRadius>();
            JI_LOG(INFO) << "Env frame: " << envFrame;
            JI_LOG(INFO) << "Goal: " << goal;
            goal = envFrame * goal;
            JI_LOG(INFO) << "Goal in robot's frame: " << goal;
            runPlanner<Scenario, Algorithm>(
                options, envFrame, options.env(), goal, goalRadius,
                options.checkResolution(0.1));
        } else {
            throw std::invalid_argument("bad scenario: " + options.scenario());
        }
    }

    template <class Algorithm>
    void runSelectPrecision(const demo::AppOptions& options) {
        // TODO: revert this.  For now keeping it out the float branch
        // should double the compilation speed.
        
        // if (options.singlePrecision()) {
        //     runSelectScenario<Algorithm, float>(options);
        // } else {
        JI_LOG(INFO) << "using precision: double";
        runSelectScenario<Algorithm, double>(options);
        // }
    }

    void runSelectPlanner(const demo::AppOptions& options) {
        JI_LOG(INFO) << "using planner: " << options.algorithm();
        if (options.algorithm() == "rrt")
            runSelectPrecision<mpl::PRRT>(options);
        else if (options.algorithm() == "cforest")
            runSelectPrecision<mpl::PCForest>(options);
        else
            throw std::invalid_argument("unknown algorithm: " + options.algorithm());
    }
}
