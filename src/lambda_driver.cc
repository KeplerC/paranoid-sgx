/*
 *
 * Copyright 2018 Asylo authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <iostream>
#include <string>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "asylo/client.h"
#include "asylo/util/logging.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "src/proto/hello.pb.h"

ABSL_FLAG(std::string, enclave_path, "", "Path to enclave to load");
ABSL_FLAG(std::string, scenario, "", "Path to enclave to load");
ABSL_FLAG(std::string, algorithm, "", "Path to enclave to load");
ABSL_FLAG(std::string, coordinator, "", "Path to enclave to load");

ABSL_FLAG(std::string, jobs, "4", "Path to enclave to load");
ABSL_FLAG(std::string, env, "", "Path to enclave to load");
ABSL_FLAG(std::string, env_frame, "", "Path to enclave to load");

ABSL_FLAG(std::string, robot, "", "Path to enclave to load");
ABSL_FLAG(std::string, goal, "", "Path to enclave to load");
ABSL_FLAG(std::string, goal_radius, "", "Path to enclave to load");


ABSL_FLAG(std::string, start, "", "Path to enclave to load");
ABSL_FLAG(std::string, min, "", "Path to enclave to load");
ABSL_FLAG(std::string, max, "", "Path to enclave to load");

ABSL_FLAG(std::string, problem_id, "", "Path to enclave to load");
ABSL_FLAG(std::string, time_limit, "", "Path to enclave to load");
ABSL_FLAG(std::string, check_resolution, "", "Path to enclave to load");

ABSL_FLAG(std::string, discretization, "", "Path to enclave to load");
ABSL_FLAG(std::string, is_float, "", "Path to enclave to load");

      



int main(int argc, char *argv[]) {
  absl::ParseCommandLine(argc, argv);

  // Part 1: Initialization

  asylo::EnclaveManager::Configure(asylo::EnclaveManagerOptions());
  auto manager_result = asylo::EnclaveManager::Instance();
  LOG_IF(QFATAL, !manager_result.ok()) << "Could not obtain EnclaveManager";

  // Create an EnclaveLoadConfig object.
  asylo::EnclaveLoadConfig load_config;
  load_config.set_name("lambda_driver");

  // Create an SgxLoadConfig object.
  asylo::SgxLoadConfig sgx_config;
  asylo::SgxLoadConfig::FileEnclaveConfig file_enclave_config;
  file_enclave_config.set_enclave_path(absl::GetFlag(FLAGS_enclave_path));
  *sgx_config.mutable_file_enclave_config() = file_enclave_config;
  sgx_config.set_debug(true);

  // Set an SGX message extension to load_config.
  *load_config.MutableExtension(asylo::sgx_load_config) = sgx_config;

  asylo::EnclaveManager *manager = manager_result.ValueOrDie();
  asylo::Status status = manager->LoadEnclave(load_config);
  LOG_IF(QFATAL, !status.ok()) << "LoadEnclave failed with: " << status;

  // Part 2: Secure execution

  asylo::EnclaveClient *client = manager->GetClient("lambda_driver");
  asylo::EnclaveInput input;
  asylo::EnclaveOutput output;

  hello_world::MP_Lambda_Input lambda_input;

  lambda_input.set_scenario(absl::GetFlag(FLAGS_scenario));
  lambda_input.set_algorithm(absl::GetFlag(FLAGS_algorithm));
  lambda_input.set_coordinator(absl::GetFlag(FLAGS_coordinator));

  lambda_input.set_jobs(absl::GetFlag(FLAGS_jobs));
  lambda_input.set_env(absl::GetFlag(FLAGS_env));
  lambda_input.set_env_frame(absl::GetFlag(FLAGS_env_frame));


  lambda_input.set_robot(absl::GetFlag(FLAGS_robot));
  lambda_input.set_goal(absl::GetFlag(FLAGS_goal));
  lambda_input.set_goal_radius(absl::GetFlag(FLAGS_goal_radius));

  lambda_input.set_start(absl::GetFlag(FLAGS_start));
  lambda_input.set_min(absl::GetFlag(FLAGS_min));
  lambda_input.set_max(absl::GetFlag(FLAGS_max));

  lambda_input.set_problem_id(absl::GetFlag(FLAGS_problem_id));
  lambda_input.set_time_limit(absl::GetFlag(FLAGS_time_limit));
  lambda_input.set_check_resolution(absl::GetFlag(FLAGS_check_resolution));

  lambda_input.set_discretization(absl::GetFlag(FLAGS_discretization));
  lambda_input.set_is_float(absl::GetFlag(FLAGS_is_float));

  *input.MutableExtension(hello_world::lambda_input) = lambda_input;


  status = client->EnterAndRun(input, &output);
  
  // Part 3: Finalization

  asylo::EnclaveFinal empty_final_input;
  status = manager->DestroyEnclave(client, empty_final_input);
  LOG_IF(QFATAL, !status.ok()) << "DestroyEnclave failed with: " << status;

  return 0;
}