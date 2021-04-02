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

#include <cstdint>
#include "absl/base/macros.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/escaping.h"
#include "asylo/trusted_application.h"
#include "asylo/util/logging.h"
#include "asylo/util/status.h"
#include "asylo/crypto/aead_cryptor.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/util/status_macros.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "capsule.h"
#include "memtable.hpp"
#include "hot_msg_pass.h"
#include "common.h"
#include "src/proto/hello.pb.h"
#include "src/util/proto_util.hpp"

namespace asylo {

    namespace {
        // Dummy 128-bit AES key.
        constexpr uint8_t kAesKey128[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                          0x06, 0x07, 0x08, 0x09, 0x10, 0x11,
                                          0x12, 0x13, 0x14, 0x15};
        std::unique_ptr <SigningKey> signing_key;

        // Helper function that adapts absl::BytesToHexString, allowing it to be used
        // with ByteContainerView.
        std::string BytesToHexString(ByteContainerView bytes) {
            return absl::BytesToHexString(absl::string_view(
                    reinterpret_cast<const char *>(bytes.data()), bytes.size()));
        }

        // signs the message with ecdsa signing key
        const std::vector <uint8_t> SignMessage(const std::string &message) {
            signing_key = EcdsaP256Sha256SigningKey::Create().ValueOrDie();
            std::vector <uint8_t> signature;
            ASYLO_CHECK_OK(signing_key->Sign(message, &signature));
            return signature;
        }

        // verify the message with ecdsa verfying key
        const Status VerifyMessage(const std::string &message, std::vector <uint8_t> signature) {
            std::unique_ptr <VerifyingKey> verifying_key;
            ASYLO_ASSIGN_OR_RETURN(verifying_key,
                                   signing_key->GetVerifyingKey());
            return verifying_key->Verify(message, signature);
        }

        // Encrypts a message against `kAesKey128` and returns a 12-byte nonce followed
        // by authenticated ciphertext, encoded as a hex string.
        const StatusOr <std::string> EncryptMessage(const std::string &message) {
            std::unique_ptr <AeadCryptor> cryptor;
            ASYLO_ASSIGN_OR_RETURN(cryptor,
                                   AeadCryptor::CreateAesGcmSivCryptor(kAesKey128));

            std::vector <uint8_t> additional_authenticated_data;
            std::vector <uint8_t> nonce(cryptor->NonceSize());
            std::vector <uint8_t> ciphertext(message.size() + cryptor->MaxSealOverhead());
            size_t ciphertext_size;

            ASYLO_RETURN_IF_ERROR(cryptor->Seal(
                    message, additional_authenticated_data, absl::MakeSpan(nonce),
                    absl::MakeSpan(ciphertext), &ciphertext_size));

            return absl::StrCat(BytesToHexString(nonce), BytesToHexString(ciphertext));
        }

        const StatusOr <CleansingString> DecryptMessage(
                const std::string &nonce_and_ciphertext) {
            std::string input_bytes = absl::HexStringToBytes(nonce_and_ciphertext);

            std::unique_ptr <AeadCryptor> cryptor;
            ASYLO_ASSIGN_OR_RETURN(cryptor,
                                   AeadCryptor::CreateAesGcmSivCryptor(kAesKey128));

            if (input_bytes.size() < cryptor->NonceSize()) {
                return Status(
                        error::GoogleError::INVALID_ARGUMENT,
                        absl::StrCat("Input too short: expected at least ",
                                     cryptor->NonceSize(), " bytes, got ", input_bytes.size()));
            }

            std::vector <uint8_t> additional_authenticated_data;
            std::vector <uint8_t> nonce = {input_bytes.begin(),
                                           input_bytes.begin() + cryptor->NonceSize()};
            std::vector <uint8_t> ciphertext = {input_bytes.begin() + cryptor->NonceSize(),
                                                input_bytes.end()};

            // The plaintext is always smaller than the ciphertext, so use
            // `ciphertext.size()` as an upper bound on the plaintext buffer size.
            CleansingVector <uint8_t> plaintext(ciphertext.size());
            size_t plaintext_size;

            ASYLO_RETURN_IF_ERROR(cryptor->Open(ciphertext, additional_authenticated_data,
                                                nonce, absl::MakeSpan(plaintext),
                                                &plaintext_size));

            return CleansingString(plaintext.begin(), plaintext.end());
        }
    }

    class HelloApplication : public asylo::TrustedApplication {
    public:
        HelloApplication() : visitor_count_(0) {}

        /*
          We can allocate OCALL params on stack because params are copied to circular buffer.
        */
        void put_ocall(capsule_pdu *dc){
            OcallParams args;
            args.ocall_id = OCALL_PUT;
            args.data = dc;
            HotMsg_requestOCall( buffer, requestedCallID++, &args);
            //                LOG(INFO) << "= Encryption and Decryption =";
            //                std::string result;
            //                ASYLO_ASSIGN_OR_RETURN(result, EncryptMessage(visitor));
            //                LOG(INFO) << "encrypted: " << result;
            //                ASYLO_ASSIGN_OR_RETURN(result, DecryptMessage(result));
            //                LOG(INFO) << "decrypted: " << result;
            //                LOG(INFO) << "= Sign and Verify =";
            //                LOG(INFO) << "signed: " << reinterpret_cast<const char*>(SignMessage(visitor).data());
            //                LOG(INFO) << "verified: " << VerifyMessage(visitor, SignMessage(visitor));
        }

        int HotMsg_requestOCall( HotMsg* hotMsg, int dataID, void *data ) {
            int i = 0;
            const uint32_t MAX_RETRIES = 10;
            uint32_t numRetries = 0;
            int data_index = dataID % (MAX_QUEUE_LENGTH - 1);

            //Request call
            while( true ) {

                HotData* data_ptr = (HotData*) hotMsg -> MsgQueue[data_index];
                sgx_spin_lock( &data_ptr->spinlock );

                if( data_ptr-> isRead == true ) {
                    data_ptr-> isRead  = false;
                    OcallParams *arg = (OcallParams *) data;

                    hello_world::CapsulePDU out_dc;
                    asylo::CapsuleToProto((capsule_pdu *) arg->data, &out_dc);

                    std::string out_s;
                    out_dc.SerializeToString(&out_s);
                    data_ptr->data = primitives::TrustedPrimitives::UntrustedLocalAlloc(out_s.size());
                    data_ptr->size = out_s.size();    
                    memcpy(data_ptr->data, out_s.c_str(), data_ptr->size);

                    data_ptr->ocall_id = arg->ocall_id;
                    sgx_spin_unlock( &data_ptr->spinlock );
                    break;
                }
                //else:
                sgx_spin_unlock( &data_ptr->spinlock );

                numRetries++;
                if( numRetries > MAX_RETRIES ){
                    printf("exceeded tries\n");
                    sgx_spin_unlock( &data_ptr->spinlock );
                    return -1;
                }

                for( i = 0; i<3; ++i)
                    _mm_sleep();
            }

            return numRetries;
        }

        void EnclaveMsgStartResponder( HotMsg *hotMsg )
        {
            int dataID = 0;

            static int i;
            sgx_spin_lock(&hotMsg->spinlock );
            hotMsg->initialized = true;
            sgx_spin_unlock(&hotMsg->spinlock);

            while( true )
            {

                if( hotMsg->keepPolling != true ) {
                    break;
                }

                HotData* data_ptr = (HotData*) hotMsg -> MsgQueue[dataID];
                if (data_ptr == 0){
                    continue;
                }

                sgx_spin_lock( &data_ptr->spinlock );

                if(data_ptr->data){
                    //Message exists!
                    EcallParams *arg = (EcallParams *) data_ptr->data;
                    capsule_pdu *dc = (capsule_pdu *) arg->data;

                    switch(arg->ecall_id){
                        case ECALL_PUT:
                            //printf("[ECALL] dc_id : %d\n", dc->id);
                            LOG(INFO) << "[CICBUF-ECALL] transmitted a data capsule pdu";
                            put_memtable((capsule_pdu *) arg->data);
                            LOG(INFO) << "DataCapsule payload.key is " << dc->payload.key;
                            LOG(INFO) << "DataCapsule payload.value is " << dc->payload.value;
                            break;
                        default:
                            printf("Invalid ECALL id: %d\n", arg->ecall_id);
                    }

                    data_ptr->data = 0;
                }

                data_ptr->isRead      = true;
                sgx_spin_unlock( &data_ptr->spinlock );
                dataID = (dataID + 1) % (MAX_QUEUE_LENGTH - 1);
                for( i = 0; i<3; ++i)
                    _mm_pause();
            }
        }

        // Fake client
        asylo::Status Run(const asylo::EnclaveInput &input,
                          asylo::EnclaveOutput *output) override {


            if (input.HasExtension(hello_world::enclave_responder)) {
                HotMsg *hotmsg = (HotMsg *) input.GetExtension(hello_world::enclave_responder).responder();
                EnclaveMsgStartResponder(hotmsg);
                return asylo::Status::OkStatus();
            }

            //Then the client wants to put some messages
            buffer = (HotMsg *) input.GetExtension(hello_world::buffer).buffer();
            requestedCallID = 0;
            counter = 0;

            //capsule_pdu dc[10];
            //simulate client do some processing...
            sleep(3);
            // TODO: there still has some issues when the client starts before the client connects to the server
            // if we want to consider it, probably we need to buffer the messages

            for( uint64_t i=0; i < 1; ++i ) {
                LOG(INFO) << "[ENCLAVE] ===CLIENT PUT=== ";
                LOG(INFO) << "[ENCLAVE] Generating a new capsule PDU ";
                //asylo::KvToCapsule(&dc[i], i, "default_key", "original_value");
                put("default_key_longggggggggggggggggggggggg", "default_value_longggggggggggggggggggggggg");
            }
            sleep(2);

            for( uint64_t i=0; i < 1; ++i ) {
                //dc[i].id = i;
                LOG(INFO) << "[ENCLAVE] ===CLIENT GET=== ";
                capsule_pdu* tmp_dc = get(i);
                LOG(INFO) << "DataCapsule payload.key is " << tmp_dc->payload.key;
                LOG(INFO) << "DataCapsule payload.value is " << tmp_dc->payload.value;
            }


            //benchmark();

            return asylo::Status::OkStatus();
        }

    private:
        uint64_t visitor_count_;
        MemTable memtable;
        HotMsg *buffer;
        int requestedCallID;
        int counter;

        /* These functions willl be part of the CAAPI */
        bool put_memtable(capsule_pdu *dc) {
            memtable.put(dc);
            return true;
        }
        void put(capsule_pdu *dc) {
            put_memtable(dc);
            put_ocall(dc);
        }
        void put(std::string key, std::string value) {
            capsule_pdu dc;
            asylo::KvToCapsule(&dc, counter++, key, value);
//            LOG(INFO) << "DataCapsule payload.key is " << dc.payload.key;
//            LOG(INFO) << "DataCapsule payload.value is " << dc.payload.value;
            put(&dc);
        }

        capsule_pdu *get(capsule_id id){
            //capsule_pdu out_dc;
            LOG(INFO) << "DataCapsule id is " << (int)id;
            return memtable.get(id);
        }

        void benchmark(){

            put("6284781860667377", "2_o?.,Fg+S)'(~*");
            put("8517097267634966", "&^?");
            put("1820151046732198", "2+!,*)Ok64:Cc#");
            put("4052466453699787", "-T?(9,!40");
            put("3232700585171816", ")U#");
            put("1000385178204227", ")>$,[cH%-");
            put("7697331399106995", "/0`3j9(p'2l;i&");
            put("5465015992139406", "9UgY!&:*%5~?&>9");
            put("6873002678636213", ".2l6#,4Ng;,h-3|#");
            put("9105318085603802", "40j;J)8?6%5<3U)!");
            put("2408371864701034", "$F7$N9=3f/'6$':1");
            put("4640687271668624", "");
            put("2644479767202980", "$");
            put("4121643602353910", "<H}'Be5A!0'>$?68");
            put("7109110581138159", "5R70L%6_#,6");
            put("4876795174170569", "7/`.1|%?");
            put("7461223496605049", "1!(");
            put("8753205170136912", "6Tk6&&+No:R73?t;");
            put("2996592682669871", "(Va/-x&-|>^%<Rq?");
            put("5228908089637460", "2C39D=!Y3%;v)4b7");
            put("2056258949234144", ";So.Gq:'8!*b.7z>");
            put("1760564577334453", "7[y6M;)Xw3P#?Je;");
            put("6520889763169322", "!+x?T)-/.!P&_9$");
            put("4288574356201733", "'$h&Ja'Go3Ck6V-$");
            put("8049444314573886", "%.><=>%0:-1f");
            put("8164984352168075", "5_5-_}D}6Me$_/-");
            put("3584813500638707", "%E5=5,K#+h+2v7");
            put("5817128907606296", "+");
            put("1468038131265307", "5Ai+Lk1[3-G-+[9,");
            put("7642772757022816", "$+$T%&(t?90");
            put("5932668945200486", ":2<8E5%8r+");
            put("3700353538232897", "2@+");
            put("3931898588792031", "09x2;f?9n/%:;)r3");
            put("6164213995759621", "9F9!]o&Mg&*/Kk/");
            put("5327322251431469", "%19F?9>*([/8Pk#");
            put("1699583181824442", "2Gy3^i<:&,]10");
            put("5585583857047162", ";Z?<7(0-v&N/?9p7");
            put("3353268450079572", ")Oa+He4-z#Dy.Q+");
            put("8396529402727210", "*Ck*Mq':l;Wm:V:");
            put("7817899264014751", "");
            put("4520119406760868", ";DmF+%*:574##v/");
            put("6752434813728457", "*_!,0&?5n>,f;;<");
            put("5548859282568936", ".De+;(2W#%&t+Y'=");
            put("2287803999793278", "0688(|'!z*:,)7&)");
            put("4997363039078325", "50");
            put("2765047632110736", "0Z%(F-9D'=1z2:v&");
            put("8984750220696046", "7Uw+5b;Ue;+n8^g&");
            put("7229678446045915", "8Ee7:,+I+,$d'8`;");
            put("5108340224729704", ".1~:E!>(d&0z");
            put("7340655631697293", "0^y2Gi4*,$Sy0G?<");
            put("6437094107945257", ")Gi.OuFw&4&-W7%");
            put("2876024817762115", "-J==.n0;z78h$Xs'");
            put("4409142221109489", "+4$-]?$-d#A32T}:");
            put("2176826814141900", "?B!0/&");
            put("8873773035044668", "*Cc2)v(Ko*^}7]u:");
            put("6641457628077078", "$)f8r'Cq#Wo</08");
            put("5696561042698540", "1@=-_s2>|;6b8S{;");
            put("7928876449666130", "2Y'=2$.7r/:v6%2-");
            put("1231930228763362", ">Me&K{.Z;09%6|6");
            put("3464245635730951", "1@9==t");
            put("3820921403140653", "$7r#3n*+p.^?");
            put("1588605996173063", ">-8!Xk/9d;");
            put("8285552217075831", "*E{#N/6:d");
            put("6053236810108242", "*)v3@+-;$%900?");
            put("7456195669291483", "+Se#>2+S=,Yo51b.");
            put("5223880262323894", "9Eo'9h4Hm.Qo6-z?");
            put("6525917590482889", "5!.1((!Eq");
            put("8758232997450478", "$6:<No?<0(U'&U%8");
            put("1473065958578873", "**~&<v7(d?S{&!b+");
            put("3705381365546463", "7");
            put("2991564855356304", "!5:,&2/$*8Ba>M'0");
            put("7592494483887154", "332<_=&6h/<f+Mc6");
            put("6867974851322647", "%+-.n//(-!4>L}>");
            put("4635659444355057", "-8p6<~/*`*'27V!8");
            put("7114138408451725", "5+d>!$!V?9A'7t3");
            put("9100290258290236", "-(.=_}4,*)8l;Os:");
            put("2061286776547710", "#_g>0d3=61Nq,F51");
            put("4293602183515299", "1@a..~&((8B;5$<1");
            put("2403344037387468", "5Ki2Km8(,$;&4U!!");
            put("1710286304198790", "'U55@u:W7-4j51t'");
            put("6279754033353810", "')*<Hc&;h3:<H#=");
            put("4047438626386221", "6&*,/t&Ii*T=!86%");
            put("7702359226420561", "'56=P16=882`'r'");
            put("8512069440321400", "64|3;(!z:N'4Q}.");
            put("2649507594516546", "8F=88n'h'F;;9.4");
            put("4881823001484136", "3R-11j?_1$+2;$x:");
            put("1815123219418632", "0|&3<Ga#3<.Ao");
            put("4171921875489572", ".;v3=00$f>)6Xq'");
            put("5691533215384974", "9N!4,t9>r;(n6(");
            put("3459217808417385", "<%v;W=1>91(=Hm7");
            put("8290580044389398", "3'");
            put("7923848622352564", "%Xk:V!/");
            put("3237728412485383", "12xMq;.");
            put("5470043819452972", "&<,8't");
            put("1226902401449795", "82t>E-");
            put("1005413005517793", "03j;A'0@!4?z71>=");
            put("8637665132542722", "#=8=I3/$-Nq4Ou?");
            put("7576763534199239", "&+,<%.+No*~2");
            put("4173034318607543", "!L)$9n2~:!f#$>9");
            put("6405349725575133", "#0>$Om+Jw'Yq0Go7");
            put("8798173132964713", "5S!8+t6[1,I-18d.");
            put("1352498093671118", "2B5$.<2]30>*?A'9");
            put("5344448127231650", "5Ua#F'/7(=/t&Rw2");
            put("3112132720264060", "4*59d$0.<%f");
            put("9220858123197992", "-5.=<61.=Ag>@9");
            put("6988542716230403", ">Ka?Vg(-$8)n(6&5");
            put("4761255136576380", "9Kg34>(?:5%z)Su6");
            put("6993570543543969", "8945Mq+Gq>^k#Z'=");
            put("2915964953276350", ".;,9Y!!Aw7;z)Jm#");
            put("1940718911639954", "?Jy:/r<;<);d-M5-");
            put("4756227309262813", "1D&F-/(40Ui6Mq.");
            put("2523911902295224", "#.,!Sy1Wm_{7V-5");
            put("8632637305229156", ">X-%8`'K}24l=_50");
            put("6400321898261566", "*=&!+");
            put("5349475954545216", "#0<,W7$$b/H!=Q70");
            put("7581791361512805", "+R+0Ji)Z9$De90~?");
            put("2966243226412012", "[{?5j$W3$E=)749");
            put("2528939729608790", "4Zi6B-'Ju/&88U-%");
            put("4168006491293977", "3Xu:/");
            put("1935691084326388", "%+4,N';v2Sa&!0)");
            put("8044416487260319", "?(n*?08@-,(r8/,5");
            put("5812101080292730", "3T+!)~");
            put("5937696772514052", "&x?Q==024H#'Km?");
            put("8170012179481642", "&7|.&6-W5908;*x.");
            put("8848451406100376", ":C=0[y&64%9b9R58");
            put("3117160547577627", ";V3=S9;$t:Ay)z>");
            put("3579785673325141", "K{?Yg$><(Ti%3*=");
            put("1347470266357551", "/b#_9=>z?5t4Za");
            put("2750429125540792", "8Fu71h-72!668S15");
            put("5181137185732034", "");
            put("7215059939475971", "++65;4<Us/+l0Ju'");
            put("4982744532508382", "/E?43");
            put("6178832502329564", ">&l2T5/V/)[+P");
            put("8411147909297154", ":Da6$?G)<2$&Z)5");
            put("1714201688394385", "'52=/n(C)1F43f7");
            put("3946517095361975", "'<$c*'d&7z*R?!");
            put("2162208307571956", "13t%:-78(#0#O/,");
            put("7010709939563285", ";)>1-z*N3");
            put("6626839121507135", ":4");
            put("4394523714539545", "/:&$Na*Aw67j");
            put("6767053320298401", "6Uq>/(Pc?<");
            put("8999368727265990", ":Iy7Vi<O}#6:D15");
            put("2302422506363222", "*P+4'b>$>8@;=V--");
            put("4534737913330811", ",");
            put("1573987489603120", "1Pk?Oi!)r:Ha#Ee>");
            put("6583279173644691", "*2z7.n&M%9K5$Sg7");
            put("6038618303538299", ";Gm3#v+Is+=(<'>4");
            put("3806302896570709", ".3$0Dq264]a3E55");
            put("7355274138267237", ")A#84d9[79+v<5");
            put("8859154528474724", "+`I982=/0*I)1");
            put("2890643324332058", "25b2Ho.#z6n)8r2");
            put("5122958731299648", ")Hy&=*=V+89:+Yi>");
            put("9857666716342838", "_%4D91T;5H{");
            put("1246548735333305", "75r.H)&7z:X*%h:");
            put("5450397485569462", "6M+&2*Xm+440<$<");
            put("3218082078601873", "3-f2P}!'n2Je2Eq;");
            put("7943494956236073", "");
            put("8270933710505888", "<Mw.Dg>^#");
            put("3478864142300894", ")^a&B{");
            put("5711179549268484", "!,x>V52F;1Is&'h7");
            put("5103312397416138", "*@=-;f$z#T+");
            put("2870996990448548", "()&%Z;38*=Gs)8|");
            put("8878800862358234", "2O'1Ni/@q&bD))");
            put("7335627804383727", "(F7=_%?F{?Z5$%t+");
            put("3825949230454219", "$4");
            put("6058264637421808", ".7|&8z5>d'*:#])4");
            put("6386815834809594", "5#");
            put("1593633823486629", "<8:9Y;9+r'-:)068");
            put("4515091579447301", "25v3-vZ{;A7-G'!");
            put("2282776172479712", "%r#6h5]e#L*Ck#");
            put("8979722393382480", "86bQ9Rq*V;:)21");
            put("6747406986414891", "3:~3,~3*d&*z1Ca");
            put("4414170048423055", ":=81");
            put("6646485455390645", "Mk6F$4<'j<Z=,");
            put("5046076551212311", "?>");
            put("2181854641455466", "<v'Xq<*xK%;#*4");
            put("3926870761478465", "");
            put("1694555354510876", "8Uo>U}3R5=*4]=(");
            put("8391501575413644", "0L;0Q1*=,83.!9|/");
            put("6159186168446054", "='8%x%F}.^o");
            put("5002390866391892", "-Iu?W%'@%-J#3:x'");
            put("7234706273359481", ">S{?!r3;92f1Oy+");
            put("5377600524567132", "/I59Q/-0@{.+*4");
            put("2770075459424302", ":");
            put("3338649943509629", "!A+<<.Jo'O},T5(");
            put("1106334536542039", "(Yu+_#5#<0L-0>$0");
            put("7803280757444808", ":h7P0R)(K#>98");
            put("5570965350477218", ".Kc#(2>-r'E?>Y}>");
            put("5590611684360728", "$(lK%&Pk/<d&?:-");
            put("7822927091328317", "+118l+1$-.t-B/(");
            put("1125980870425549", "-<z7Ay5T=%1:=;~6");
            put("3358296277393138", ".:f*'.0'j;U-'p/");
            put("1955337418209897", "992%");
            put("4187652825177487", "<!858f%=t7Si%=48");
            put("2509293395725280", "6Ho*+|<A7-E39");
            put("2769779887576915", ".B!8Fo&V)%?t-0l&");
            put("7562145027629296", "&Ka3Z/,#~#31?v2");
            put("5329829620661706", "0*r61~4Q?(5Zu7");
            put("6419968232145076", "!1<)Hu&Eq*");
            put("8652283639112666", "$08)$t2M!$S/=5&=");
            put("2543558236178734", "0Kw/0&0&<)L-<9f&");
            put("4775873643146323", "=D'0-p)+t'&,;P'9");
            put("1921072577756444", "3!`/(v5[m;y;/:4");
            put("3112428292111447", "$Jw7#r$S!)<");
            put("6973924209660459", "<Ce?-b!R#,,~=N9,");
            put("4741608802692870", "7$z/:<58d6]}3_i?");
            put("7008189050113913", "2");
            put("9206239616628049", "%Q?9&2.^=0#0<+*)");
            put("3131779054147570", "/W?1*d!N?E%?9r3");
            put("5364094461115159", "37p+#~)Z'5<*:P{3");
            put("1332851759787608", "N9,X9#Po'(d*U)%");
            put("8994636471799811", ":?>4X!!Yq#Hw&P}");
            put("6385703391691623", ".C5<Ec/T+-S#0");
            put("4153387984724034", "&%f#*6>4");
            put("7596409868082749", ")$`&K7%B=4*$8Cy:");
            put("8618018798659212", "8Jc./-^#<Yo3X)(");
            put("3719999872116406", ">^?5;z,18838>Q?(");
            put("5952315279083996", "%O?(^i.Vu7R3+44)");
            put("7446309418187719", ",7f#Cy//f/4:1<b#");
            put("1487684465148817", "6");
            put("5797482573722787", "$[;=^!;B/5>:4Gm;");
            put("3565167166755197", "&Q?1Fs!,n&#p.,$=");
            put("8184630686051585", ".5x#'~#/j&:");
            put("8029797980690376", "'*()Mm7105$z)+8$");
            put("3975458536654475", "%Cy+L)<8t?]3!%>,");
            put("1834769553302141", "=@{.U+?K=,/p5R{.");
            put("4862176667600626", "7&");
            put("2629861260633036", "!J7$*v60v&<z,9&(");
            put("8531715774204910", "&<0%$(0Uo>=j17`:");
            put("7682712892537052", "?-,,Qc;P1=!n<<(");
            put("4067084960269731", ")-:$Vu*[9%E3;&n7");
            put("6299400367237320", "8o2L/3y&B}&3n3");
            put("1906749643033888", "+E9=Zu7,j.#206t*");
            put("2422990371270978", "!(<Wo%G7=<`");
            put("4273955849631789", "+E+$Gs");
            put("2041640442664200", "9j*]s?Jw#R}43f?");
            put("9119936592173746", ";7x:1v3$x28$-C?)");
            put("7094492074568215", "9");
            put("4655305778238567", "Eq24r#',,;n09.=");
            put("6887621185206157", "4/8(9p*Co7D33_i'");
            put("7788957822722251", ":F;$&z&580_'4)>%");
            put("3011211189239814", ":'(=@e(44!1&5<.0");
            put("3685735031662953", "2y6J=5Q{21z9L;");
            put("1453419624695364", "#Ku;V#&?((Zy?%,8");
            put("8738586663566968", ",?$='2/(<0[=2^}6");
            put("6506271256599379", ";.j'U3#>|+1h?Sq*");
            put("5243526596207403", "");
            put("7475842003174993", "#P}6N;#*80&r6?,%");
            put("1367116600241061", "8H'<'`0Z')");
            put("3599432007208650", "0'z><`/_E';V%)");
            put("3097514213694117", "2U+9*&'?$,Qu(+60");
            put("8651988067265279", "*=");
            put("8150365845598132", "!$48L*9x/Wu'g3");
            put("5918050438630543", "/=x&o?^98Fe%=>8");
            put("5831747414176240", ",Y-");
            put("8064062821143829", "-Kw'Eg'56!.~:B?8");
            put("2056600594528442", ".,25_+>D)4,*9!");
            put("5701465539935650", "+Vy^y#5|>:H?1");
            put("2408030219406736", "49,,1x?H?,R+6Cq*");
            put("8280647719838722", "!-4,[1/&j>");
            put("7460881851310751", "W19?j,Os/(5/|+");
            put("3227796087934707", ";Qu7N1,Ls>1t8E+9");
            put("6521231408463621", "/(l6,2(*&<V)=y2");
            put("1236834726000471", ":N;9B=(d#b$8l'");
            put("2644821412497278", "$3>,-47<6,Zu)M7%");
            put("5113244721966814", "3I3@y+A'=D:I}*");
            put("1819809401437899", "");
            put("8868868537807558", ".Ws.2|n.,%&j6");
            put("6872661033341914", "7)6");
            put("3816016905903543", "(Q7");
            put("7109452226432457", ".<0,)`76b?0~+'>4");
            put("6486139080316352", "1'|3[m.)t;M)>N'$");
            put("3233042230466115", "!>:<;j$*t/4$.'`'");
            put("4525023903997977", "/6`:?`004,Ne$1f?");
            put("1231588583469063", ">Go&V=");
            put("8989654717933156", ":Y?()z3Hk;R7-1j.");
            put("6284440215373078", "'Mg7*|(Lg6Y#9Dm#");
            put("4404237723872379", "=@s/>v8]7");
            put("7697673044401294", "4.h'%x");
            put("6039309006279892", ";B)80;r#Uc/V%%");
            put("3821263048434951", "/Nc2;0,U-");
            put("3936803086029141", "(20-:,:Ns.S7");
            put("6433677655002271", "6$j+068Qe3=%9j?");
            put("8401433899964320", ",1v3Aw+.z;C;!Qk*");
            put("5696219397404242", "<RwFi1Cy.*(");
            put("4992458541841216", "$F9,>x'Z?8<40Dm+");
            put("8285893862370130", "(8,,U{*R3!46My&");
            put("5278277279060374", "!..9Jm");
            put("2962826773469027", "4E!");
            put("8054348811810995", "&2~+'d0Hk'Yw4/n6");
            put("4760913491282081", "/Q'$V96.)>*<)8(");
            put("5927764447963376", ".;2");
            put("8632978950523454", "<+&9K{!z2^{>7p2");
            put("8749128160593618", "#&x/Xu&T=)$0(Sq");
            put("4168348136588276", "12d7'f>A7<Oc$@u/");
            put("3589717997875816", "(V5-V71B)4(>7T?,");
            put("2919381406219336", "9$*4;j0&206>'Nu6");
            put("7466127993842159", "1Kw+:f:)<%Ie*Us;");
            put("4172692673313245", "27t&A#9,");
            put("6515985265932213", "&5l/+:/(.90j**,<");
            put("9221199768492291", "0)");
            put("1463133634028198", "$F{2Ui>'.)+z6%|");
            put("4756568954557112", "8V#,9,#S}.(+6j/");
            put("3001497179906980", ";He#Yq<");
            put("8801589585907699", "&Ma+(;<b:J=.C?");
            put("6877907175873323", "13$0Xm_'Y-)>0(");
            put("3584471855344408", "'");
            put("7104206083901049", "=;8!(<*Ea#.r0Bw'");
            put("8637323487248424", "");
            put("2051354451997034", "-+j'Xk6Qg>9,!#*-");
            put("5344789772525948", "%>*-];#Fe/505K19");
            put("2413276361938144", "!3");
            put("1468379776559606", "@wD!2:-4~07`#");
            put("6289686357904486", "-?,=c-4h>C39!&,");
            put("2996251037375572", "64t27t7(");
            put("7692426901869886", ";Li/=<,25`!,8)");
            put("8049102669279587", "37(4_g21`+]e=)p*");
            put("2639575269965870", "';*)Iy7-x#O/1R}+");
            put("5933010590494785", "");
            put("1825055543969307", "!h:X#($=74:,b.");
            put("6762367138279133", "7^'0:|,.r*]7Mg&");
            put("9956989961849596", ".$4,-4%V!0P%#W78");
            put("2297736324343954", "'>8;p'+0=Z='3,9");
            put("5460329810120138", "(E-98f=#(!T=%&2%");
            put("2755115307560060", "3Jq6).1Z39Fw-");
            put("7933562631685397", "9:~3T7)8h.Pe.[=%");
            put("7219746121495239", "0[u'Ng-2l>Tc/");
            put("3468931817750219", "$Cy#6d-90=Y5?X%");
            put("7350587956247969", "+*~2,n:,-/l*I5$");
            put("4074781782161233", "<7z?^o2Po?*r.Uo7");
            put("2885957142312790", "!&x&D!8M1-@/./4-");
            put("4872108992151302", "+p??$$.");
            put("2166894489591224", "&Gy#S)");
            put("8521783449654234", "-O%55,3My.*.!Ew3");
            put("6631525303526403", "?#|+*n)L=");
            put("4057152635719055", "2#n&<");
            put("7938808774216806", "'D1([m+=45:~2Ma");
            put("1807426397527130", "?.>5*(<O/-L'#4<<");
            put("3474177960281627", ".5=7p");
            put("4283888174182465", "-A{2:n*E3-&2()p/");
            put("1578673671622387", "5^-8U#&C/(?h6I%=");
            put("9110004267623070", ")>:!Tm>)d7@;16z2");
            put("6043304485557566", "3To:4$>H10&*3X=)");
            put("4645373453687891", "30~3Kk;,<(Z??R14");
            put("8527029592185642", "3-$!<0@?(+n6]w>");
            put("7689634577215493", "?^y>1b*");
            put("4062398778250463", "4U=0_{%?n7Uk.2p>");
            put("3695667356213629", "7_s*J96=");
            put("9904528536535515", "(*-Q5+S?$Xe?Bk");
            put("8748518988117644", "6,8)0$1)<=-x&7>9");
            put("5455083667588730", "5&24!>5H'<2v");
            put("5233594271656728", ".7>-)4-7|6Ok*_{:");
            put("4409483866403788", "7Gi3A{9+h7Oi>y+");
            put("3348582268060305", "#=d/S$.x:)f'O)=");
            put("5514694753139079", "<Oq#$~0N)");
            put("7813213081995483", "/Z}7So1K#)768E%9");
            put("5107998579435405", "&Cu+>~9K1)D!");
            put("5580679359810052", "<_s+");
            put("8874114680338966", "-320R{6K'");
            put("1116048545874873", "-%`:/<3]c*H5<T=$");
            put("4997704684372624", ":S}/:4-Gw>.|2N}>");
            put("2760361450091468", "5^34O;3E99!*(Z?,");
            put("5330738704374455", "-M35]=(M9!I?'Yi3");
            put("7224992264026647", "=.89Vq#C-)De5'&!");
            put("4519777761466569", "9R#!0l6D?$$0?j&");
            put("6168900177778888", "#=");
            put("8984408575401748", "4l.M?(2b*Vy:7t/");
            put("1704269363843710", "6G15No2Cq&F{>$(");
            put("5585925502341460", "&3l6704;z/.$;Um&");
            put("2172140632122632", ";88)=b?R{>X?184");
            put("1121294688406281", "1We;1x6+t;F%:t.");
            put("6636771446057811", "+:");
            put("3931556943497733", "'Bw3',*6l:?f,H{>");
            put("6757120995747725", "2Io:Zo.6f&He6<v?");
            put("8396187757432912", ">Ai+C?3<2<!66Zq2");
            put("2292490181812546", "2K=)c5-<15$7X!,");
            put("6174146320310297", "!'.(Iw8P+1H/");
            put("1583919814153796", ">");
            put("1709515506375118", ".Ww/B+!:8$+:=n2");
            put("6048550628088974", "?904Vg)");
            put("3343336125528896", "9>560>8&%Eg&((5");
            put("7345341813716561", "3*l#>*3]#4/*1B?<");
            put("7807966939464075", "'V=5&4");
            put("2880710999781382", "(>,");
            put("6978610391679727", "4Pg>.d>.*$R'*Ri?");
            put("3710067547565731", "&L;%$:,");
            put("7003502868094645", "-Ve*,z2(n/K,/68");
            put("7545632663694477", "K?$Z3.N'");
            put("1950651236190630", "7%t:19D#=Uy8Q!!");
            put("5807414898273462", ",%b&P))U#%S99[!)");
            put("2513979577744548", "&JmR+7]'))6Xc&");
            put("8174698361500909", "Me604!?*-Tu.Xe'");
            put("6390389573710891", "'1j:2h1^!(Qm?-4<");
            put("4298288365534567", ":Om64t=X1,;x63r2");
            put("7591723686063481", "6=80U90G%-g%:><");
            put("1663424484006114", "<*");
            put("2538872054159466", "(!)3");
            put("5219194080304626", "&_w7Oo89.");
            put("1925758759775712", "#Wg>>r?Tm7&4)J*");
            put("8762919179469746", "'E)0Y5;N;5C%=");
            put("5802168755742054", "!*6=Sw6Ge>|),j.");
            put("4886509183503403", "$!>1>8+8<%&n5Y10");
            put("8179944504032318", "1V'-L/$Gw2%b-)00");
            put("4218783695682249", "56$9D{$O-,O577b>");
            put("3127092872128302", "67<0-.'9&8(v'/");
            put("4630973262335790", ")]14Lq'Gg.'z0E-9");
            put("1337537941806875", "&V)$L%!1j>%$>!$<");
            put("9095604076270969", ">Sw/F183d&<4#Na6");
            put("5213947937773218", ",<v;@'82p.1z0P?)");
            put("5474730001472240", "*Uo?M>Jg#-v%Qk'");
            put("8768165322001154", "&J5");
            put("1010099187537061", "5+z#@%*<@1");
            put("3715313690097139", "'Ig>Mq)2&<Pu2)n#");
            put("4042752444366953", "<Dq3Tm?Yg;P;0D-$");
            put("7493171238380396", "6@=0Tu$Re'Z7>Z9$");
            put("8507383258302132", "0F-%7");
            put("9115250410154478", ".Ie.z=Gi+:z:=<5");
            put("1357184275690385", "5!b+Qk=<(5)4/1`'");
            put("4650619596219299", "<!r7L+-I?03l&By.");
            put("3107446538244793", "#',1)$5<<(8<=8<");
            put("4022320356847152", "$B1-/<3Uy6}6:8");
            put("8160298170148808", ")[s:/|'.$=7v=3v3");
            put("4866862849619894", "=/85Uw18.(U10P}'");
            put("5821815089625564", "%Jc&E58-n-`53|:");
            put("8743272845586236", "0R')6|.O=4$d17");
            put("1945405093659222", "-[19=~0Zq7[w:1v&");
            put("5238840414188136", "<F;=.62Lu',z)*<");
            put("2519225720275956", ")&");
            put("1859887822841211", "53v?i-;)5");
            put("7572077352179971", "6Eu2-6(");
            put("4278642031651057", "!]?-&(0D?)I7==");
            put("6410035907594400", "$,p>$$-+$5:n2*&5");
            put("8155052027617400", ":8p/9l21d>&*=");
            put("2533625911628058", "978<C#");
            put("5827061232156972", "/B{2=");
            put("1931004902307120", "-F!0W;?8&%,*.?x");
            put("7742096002529574", "Oa.$$>[-({&N{:");
            put("6983856534211135", ",Im;@1*,>9;f");
            put("3690421213682221", "+!d2=r(68([3+>j7");
            put("6998256725563237", "7Yg'6<#O=$Ts%Co:");
            put("7566831209648563", "3=`&#216~/=p$=|7");
            put("3121846729596894", "#Lm'Ti5)8(");
            put("6415282050125808", ":=(=J'$H994f");
            put("1342784084338284", "8Dk7S%*+6=#04Xw*");
            put("1362430418221793", "3%h>8|.Oo*,#W#5");
            put("6395635716242299", "3Kq?,r4.");
            put("3102200395713384", "6,Hw.f;Dw%Mw3");
            put("7586477543532073", "$");
            put("2272843847929036", "%B%(/d5F5-0|0/:,");
            put("8415834091316421", "1M#!46S3(+l2;=");
            put("6737474661864215", "(Bi?Xw!A}242%8b&");
            put("3951203277381243", "1>>5.&$&,-");
            put("6656417779941320", "/(n6%r&N%!+8C)");
            put("1101648354522772", "2Q3(B;.#(92r7Fk.");
            put("2191786966006142", "04f+Qk%,<4F10Ew2");
            put("5566279168457950", "4,t?Xm996,O326");
            put("1684623029960200", "6Gw;8");
            put("9004054909285258", ",Qk:!j,Zq=02$z/");
            put("6149253843895379", "");
            put("4539424095350079", "18)2v4=f.?68,4");
            put("7244638597910157", "?($1Pc.0v.2|.'x'");
            put("5134275365539358", "3@c3*f!'f3");
            put("2780007783974978", ";U'86~9Pw**j609");
            put("4978058350489114", "/L!08v')49_7;O78");
            put("1096402211991364", "//>$%l&I)5[m5C/5");
            put("8854468346455457", "<L3");
            put("5561033025926542", ")+r3Vc-:4@e+I!5");
            put("5127644913318915", "19p4b#&>)>.:51");
            put("7832859415878993", "+X'1L3-.29^+529");
            put("7479328141490053", "<]kFa55$<(z$_!1");
            put("3368228601943814", "-3*)1x(}6Tw>?<<");
            put("4389837532520278", "=,h:6");
            put("5081813940225276", "8:n:]e$,&-6~>Ki");
            put("8266247528486620", "(Ue2K{5N%=!p6*&-");
            put("4972812207957706", ",Be'M9+;0!?(;Z%<");
            put("5715865731287752", "'U=5Me83b>Uy=C3(");
            put("8421080233847829", ";Gc6<8,");
            put("6630140993837368", "6N74W71+f7#r.,l&");
            put("3956449419912651", ",Fa6*x8.><',0X-5");
            put("3801616714551441", "%[m>5p4Q%)+f;M)=");
            put("4625727119804382", "9J)9[g%;>4.+7()");
            put("6062950819441076", ":_i2Li94");
            put("9090357933739560", "1G=<?z/_g+:0*!j6");
            put("1598320005505897", ",!r3%(<Z}?&z4,j'");
            put("4303534508065975", "7(n/F2>v.9&");
            put("3454531626398117", ")Xk7Ay>D'0:>&$n");
            put("1610963058692032", "");
            put("7919162440333296", "1D3");
            put("4037506301835545", "9");
            put("6651171637409912", "8A%=^e1(*=/b?[+<");
            put("8502137115770724", "");
            put("2186540823474733", "([=8Gi7/2");
            put("4891755326034811", "&L-1Ts(!l/?,&=0%");
            put("2866310808429281", "=_k:R1#^{?=x3M7<");
            put("4271245120996330", "3Qq?-j<Iw*@;4Hc2");
            put("7330941622364460", "'66<Z)+X3");
            put("3449285483866709", "^a?Fw3^#14d2$d?");
            put("7239392455378749", "+0x;4");
            put("7913916297801888", "");
            put("2774761641443570", "#");
            put("5479976144003648", "1#2()b5@eWq54l>");
            put("2278089990460444", "9*8$|)3r/X)=O=!");
            put("1015345330068469", ",o&,0!3z+Oy560-");
            put("6742720804395623", "0]s:2<6Ec'W}',n:");
            put("2861064665897873", ":C#41j/#8%X<L+,");
            put("7827613273347585", ";@#8%|?I'4=f.2,5");
            put("7325695479833051", ":'|'D%+!n?8");
            put("3362982459412406", "$-l.Y/S/%,b;Hs6");
            put("6068196961972484", "");
            put("1689869172491608", "'^-(<(8");
            put("1603566148037305", "2A+%/6'$.!O1");
            put("6154499986426787", "4Gc!");
            put("2171580671610491", "*3t6!8/5v2Ac+%.8");
            put("1473284273796715", "0(");
            put("8170230494699484", "7A!4Ky54");
            put("4403896078578081", "4_2Y3=*z:Ls/02!");
            put("6757680956259865", ";Rs:F)76>9<:,6n/");
            put("7455977354073641", "-?f6_;7:");
            put("7590311331708735", ".Zu&Yi6]-9Cq>&d>");
            put("4525365549292276", ":!z.I?5)85,()3j>");
            put("1583359853641655", ":-x/+~:y;F=%1f>");
            put("8850634558278795", "2<h.:v?Ts?Zc(z");
            put("7582009676730647", "=W'");
            put("3815675260609244", ";4,0&~A#9Fk>54)");
            put("7345901774228702", "*-4<R;]s7@o$Gi:");
            put("8044198172042478", "43:1Ia.U#-Ja<T{2");
            put("1347251951139709", "(");
            put("5113586367261112", ",9*$Rm8Hk/.j--r?");
            put("9951390356728192", "1T}&Bi9Ae'7n4S#!");
            put("2968426378590431", "(224Ok6$>5^g6L)(");
            put("6993788858761811", "436,Me9(d/'z=U50");
            put("3227454442640408", "!J35(0%J)8Gk1X=!");
            put("7934122592197538", "4@c*A+66");
            put("8632418990011314", "$@=%R7'5`7:4,C-%");
            put("1935472769108546", "',f.^12Jo22>12<1");
            put("5701807185229948", "0;d4h=@!1Uo(@=-");
            put("4069182177039828", "8(`62v4,$!Q#");
            put("2913781801097931", ";^/9[q1+6)Uw;66!");
            put("6405568040792975", "&>");
            put("2639233624671572", ".q7Qa/Z%$Z=.769");
            put("8522343410166374", "#^15Ry2]e>;z5H!)");
            put("9220639807980150", "$J7Y1'^{7Hc");
            put("2523693587077382", "5728Ta/^5%P-6:~#");
            put("6290028003198785", "/5t7[!-6>!Z/[e:");
            put("4524463943485837", "8K)=-,2E-");
            put("3826167545672061", "37p7$.9U#8L79=21");
            put("7923630307134722", "9@'0!t4Pg?E;!M+(");
            put("6756779350453426", ")I#%%d(&*");
            put("4404797684384520", "=6`_s4F-%P!=?p+");
            put("5103094082198296", ">V/<D/9L91*|#?8$");
            put("1593852138704471", "8[;5%85;r'>l-3$0");
            put("2172482277416930", "1T#8Y-0-b#)0$Mm?");
            put("3936243125517000", "7>n7#z;T=)[q+C)!");
            put("3237946727703224", "8QaAi6/&);(9X3!");
            put("8511851125103558", "7$6,=~2L+!2(J7,");
            put("6168558532484590", ";M:P7A!,D1,G5)");
            put("4993018502353356", "+{6X?'6~;}&Ug:");
            put("5691314900167132", "8Ky*I)]u3@+::>1");
            put("1005631320735635", "9Qu7A/,B/4Xc>Wo?");
            put("2760703095385767", ">%x.#:-Jc3(5Ey6");
            put("3348022307548164", ">4--j8B=4;r<");
            put("2649725909734388", "2,9La/%x3'l_s6");
            put("9100071943072394", "&3(<U;%.*,7v>L--");
            put("5580337714515754", "-G{7U1$!n&]c<V%!");
            put("5581239320322193", "4?|3^/1$v;.v8;b;");
            put("6279535718135969", ";-$1J9-K'=E)/I?(");
            put("4174105027667991", "");
            put("3348923913354603", "=Vu2#*-Qq2Ke=Ss+");
            put("2759801489579328", "49h+Hc1W{.A1(%*4");
            put("2061505091765552", "(?v>-t-C+!!6=G3$");
            put("8758451312668320", "/U%<U}6E;5,>)@o.");
            put("4992116896546917", "$3(0@w8Xm217_{>");
            put("6169460138291029", "2*%_#:)x6Ks:Fu:");
            put("6867756536104805", "/6(Fs");
            put("1708103152020371", "58j6%p0-v.K701f>");
            put("3937144731323439", "74|:Z97&v'6n%'l/");
            put("2534185872140198", "#$j2");
            put("3232482269953974", "#]%()<75j2Gy0*v");
            put("3464463950948793", "9T!%B=,C}.&z4/2!");
            put("3018704651726094", "+.v28;u:04%!z*");
            put("6983296573698995", ";$x7Ju+>r;?d4)&");
            put("6285000175885219", ";.0)Qw#S=1_i0=-");
            put("5464797676921564", "");
            put("9215611980666584", "5,j2P'4Ns2t4N7-");
            put("3122406690109035", "1#b/+256$-Z!6Oa;");
            put("3820703087922811", "+Q94Fe6H;!$f&>f?");
            put("2876243132979956", ".Z}>Gy07x'A!$Fc:");
            put("8900912831414457", ")6p+8`4A55_)/:&!");
            put("6395075755730158", "))&,V3,:<8<6.72!");
            put("5696779357916382", ")8r>#|?D+4?x-O/%");
            put("6053018494890400", "(645Ri:!((;:+!6)");
            put("8627391162697748", "<Ky+Sc,-$!2~29.");
            put("3710627508077871", "'Y',Re01|?+({:");
            put("4408923905891647", "(Q/");
            put("2288022315011120", "4/(5[y*R3[u#O!!");
            put("1478312101110282", "%(");
            put("5806854937761322", "20,No$V5!G/1#l7");
            put("5108558539947546", "?C996j<E?46f'2b");
            put("6641239312859236", "6@q7A{!<)#(896");
            put("8039170344728911", "7?`6I'&G}2&:(7p#");
            put("4298848326046707", "-F&-`'4n&<*63");
            put("4997144723860483", "28#b1!~&/84508");
            put("1699801497042284", "4=|*'n!$l.0*85)");
            put("2066532919079118", "(Ak?^*^/0.4Qa;");
            put("5218634119792486", ">K'=8r<)&14:$A90");
            put("4520337721978710", "&7|'/v!2l#F)&Lm?");
            put("7229460130828073", "2T%-7r*!0)+:0Aa&");
            put("7450949526760075", "-Uu/R1*@+=!4=6");
            put("1813026002648534", "+LyM)'89E!(4j2");
            put("8795989980786295", "!)*--b>_5<4$='69");
            put("5817347222824138", "6Mc.I+>!=@,Eq");
            put("2051012806702735", ":^3,9(7^%<'l?-v/");
            put("9110564228135211", "7,<5H);-`/:$/Cu'");
            put("8637883447760564", "&W3$'7E7:(3Dk&");
            put("3111914405046218", "$Ka:4,<Qw.<t9S)$");
            put("6878248821167621", "%:h;5j]s?Ku9G'-");
            put("7695234182336898", "(,4=V1(R?");
            put("1467819816047465", ",K{*&d?/*9>t'(b*");
            put("5229126404855302", "I1,#((M-5N=&)l/");
            put("1462791988733899", "#>:<=2;Pg:'8&_'9");
            put("8747959027605504", "#$60_u*:~2K};=04");
            put("8049662629791728", "'Iq.B?&]{7L#5<");
            put("3700135223015055", "4]*3$");
            put("7466469639136458", "(;h3%.3Aw6&&%Yq*");
            put("1357744236202526", ".G{#.:^35D=9U!=");
            put("2056040634016302", ",N'(<~<=<9;&;Mw7");
            put("4640905586886466", "?8h'88'%$");
            put("8745711707650632", "*<<-<j=(");
            put("8159738209636667", ",#6");
            put("7461441811822891", "0Re;9l44");
            put("4288356040983891", ")%j*+x>5b7Rc$%2$");
            put("8054690457105294", ">Ea>M{(2,!t':2-");
            put("1945965054171362", "#_%$/h7Rm'F3(F-)");
            put("2644261451985138", ")G==K3?Ug.$<?O}?");
            put("4052684768917629", "7Fy&[g%5$=7`,:n;");
            put("2863503527962269", "9Vs3Uc%;t&;(&]e+");
            put("7571517391667831", "8;*%U=6-`62");
            put("6873220993854055", "+X}*Y!,(d&3,9Lq6");
            put("4876576858952727", ",[u3*h=Ic+$:4:d&");
            put("8642911275074130", "/':!6,'S%$@=*Z!)");
            put("7239952415890889", "0Ty#:f0X-");
            put("7938248813704665", "++(95~-$><B)>Ea#");
            put("1241302592801897", "0;~...(-v'Du)^}*");
            put("5007637008923300", "6*v+Cy<;b?/$/Ha&");
            put("2277530029948304", "0^o>Ze$%f:P9/]#$");
            put("1579233632134528", ">_#=3444vR{+Go?");
            put("8276179853037296", "&Y%(;v&*8-,p7G{'");
            put("4509845436915893", "#M980t8(,-I?3H;)");
            put("7828173233859725", "<(h2M747>(:<;Vm7");
            put("8526469631673501", "9O10B#15l'Kw=&48");
            put("1829523410770733", "3@c31*8]i:S1,Ci6");
            put("5595857826892136", "*5811x*?`&Jk3Ew");
            put("1689309211979468", ";-");
            put("9910128141656919", "2N#%>55`/S;2Ds?");
            put("7687959035068460", "<WiZ%");
            put("3921624618947057", "!D!%]a$W#9P-,4`+");
            put("8416394051828562", "1=0=02,Xs+T5/]+,");
            put("9114690449642338", "=)~6W'158-C}&Jm#");
            put("2417744228739570", "(_;)");
            put("6184078644860972", "=Sk3&069~/0:;S{6");
            put("1101088394010631", "#(z'*|6H50>r1K{2");
            put("4027919961968556", "/)48-,6'$,Zo7+v2");
            put("7099738217099623", "90>)=r40|2.84U.");
            put("3333403800978221", "290$7*3(5G'<,8)");
            put("9004614869797398", "5S?%/4?B)9V/");
            put("8743832806098376", "=N10<n50`3;h");
            put("3005965046708406", "6@-!!0Ie6Yu%^i#");
            put("6772299462829809", "7C}#<$)?$%(*-R'4");
            put("5128675760417953", ".Q7-L5*E75D!'*j3");
            put("1854288217719806", "<Uc/");
            put("6511517399130787", "$]-(+2)7005v>,(1");
            put("2745182983009384", ">:$%8<,/.%6+!.9");
            put("4887069144015544", "2Lm2!z6_#-K%47h;");
            put("5585365541829320", "4j&.&S;");
            put("1111580679073447", "'.f3Cc+D;49|+Jo");
            put("2654753737047954", "?!80'n+D5%A53@9<");
            put("4630413301823649", "%Ju;F/&4t?5x5Gy?");
            put("3932116904009873", "#Yk*^':/<8A!84x2");
            put("7817680948796909", "$6.<");
            put("6862728708791239", "-568Gu7Ae'K/!r7");
            put("5475289961984380", ".)");
            put("6173586359798156", "4.f:Dw,)z+_{)J+)");
            put("5233598611046116", "!Q%8O!9n.Tm7$0");
            put("3242974555016791", ">+$5Ry#])-R#5=r6");
            put("4042192483854813", "0#p?Ro1-08-v#7`6");
            put("3343896086041037", "*X'0#");
            put("8405901766765746", "5d.H9Lm#Vy0Dw>");
            put("6274507890822402", "'6<(<~>=25(:([y?");
            put("6063510779953216", "1Kk*>4/0l?;t+Ca2");
            put("6761807177766992", ":3~:'&._e76'_c?");
            put("6486095686422472", "-24<#>.W=57.28h");
            put("3831195372985627", "<>f.Ds9=v7E}:H}?");
            put("3453971665885977", "7Nq?@'4)v>#z9+n&");
            put("2755675268072201", ":X/=#v");
            put("8994122584734582", "&3`#@a#<p/1p)[50");
            put("5686287072853566", "3*j++6&(8-/z&_?");
            put("6651731597922053", "%4n7!p!Uq+W-</(%");
            put("7350027995735829", ">X)8R}4A!9E56J:");
            put("6530817748330610", "3;*4#x8/.5&f#1j&");
            put("4419416190954463", "!Xa/Yu6:($4|*Ae#");
            put("2865750847917140", "!]o.Z76@;(+(");
            put("2167454450103364", ";?8970<=,-Su=A-<");
            put("8864400671006132", "8)`20h.9x>'0,(b");
            put("5098066254884730", ";_/5J5:$n2G#,");
            put("6501025114067971", "1Dw30x6L+!");
            put("5802728716254195", "&S{6)f(<f>H9?#r&");
            put("5947069136552588", ":5l.6f'2p2D/2Y;8");
            put("8733340521035560", "5T34LaHe:Qi-&|*");
            put("2428236513802386", "8?n?T+");
            put("3126532911616162", "4Ru+Xu)G)),x95!");
            put("3570413309286605", "?1n736#E9-9z!G-1");
            put("1959211068347969", "%C;0");
            put("5912804296099134", "<=>1Zq7_k+");
            put("5214507898285358", ";7$$^!0[k.'b)v");
            put("6535289954521424", ",J+)Vc$/<1N+']w'");
            put("8145119703066724", "?189Ow$:*,*v,W95");
            put("3016457331771222", "H?9Tw:@!52?I?4");
            put("3714753729584998", "/64,,z.'h#;0+4:<");
            put("2982192491317769", "%E#)K#*?n:2t12<8");
            put("7841419248036332", ":!v.D1");
            put("5324583478130298", "/Am#-z+6n6.>+Wg?");
            put("4626287080316522", "%<r*#~4K}/[+<i;");
            put("7123510772490260", "/Be'.47Vs;%r+Go6");
            put("7556898885097888", ")Mi+4>%E1=,b-Sy*");
            put("3604678149740059", "('>-?n+:8!M/&Tq#");
            put("4302974547553835", "20=$*3Zs2Gs:/|");
            put("2393971673348933", "0<b*'n+(");
            put("1372362742772469", "!)(</0#Se2?j$!(");
            put("4736362660161462", "2Pu+N-;X75#&>Ow&");
            put("4038066262347686", ",50%3>=X!,*j!Kq;");
            put("7711731590459097", ",G%!Iq'9`?):&Cg2");
            put("6968678067129051", "9#|;#l,=($Ha;9<,");
            put("4192898967708895", "2.v'^#</|/)6>Ci2");
            put("4891195365522671", "&&(8)$=n3V;/Va");
            put("1805750855380096", ")Q><,,");
            put("1960583560741305", "$&v6^1C-$^/.Za;");
            put("8853908385943316", "-L94G3//t&");
            put("8155611988129540", "7X%5~2/x2,n?C5!");
            put("3594185864677242", "+$<Ok<Fw6b>[9%");
            put("7360520280798645", "8R#8(tW{.V%;Ii/");
            put("7535324192704098", "'O#Qw4Ym+$6/L1%");
            put("7736496397408170", "3+(Vo");
            put("5923296581161951", "87!-x8':$@u.2:(");
            put("2156962165040548", ")Fa??21[y3&");
            put("8265687567974480", "'6f#");
            put("7567391170160704", "/;v2F%=[y>%~?>b3");
            put("4182406682646079", "4<&<Xq");
            put("7948741098767481", ".Wo:F!/&l'Z17*)");
            put("6635740598958773", "1Z}#Qw<O70Iu?@+");
            put("1361870457709653", "!9p:Ee8");
            put("5335075763193114", "$X75:x5^;8)~7!z;");
            put("1568741347071712", ":Vg.6$,?:9*j");
            put("7677466750005643", ")/8)Ga");
            put("6979170352191867", "<R%$(x#J79-b'S-0");
            put("4770627500614915", "._?8E38D;=Ga*1,");
            put("8536961916736318", "Om?#0:_u7I+6Co*");
            put("1251794877864713", "6A#!C+;J-02*8T+8");
            put("1950091275678489", "7@w2000:p3[q;5.!");
            put("4746854945224278", "7w;Qo+Ek?)v&6$");
            put("9805205291028757", "=D%))0)381,p8Bo");
            put("7089245932036807", "<86=Oy.^k7I!$0!");
            put("6390949534223031", "&400I;.F{?&(!8,)");
            put("5358848318583751", "#4.12`/5|>(j-$6<");
            put("9125182734705154", ">6&9@5+W--+4!Lm.");
            put("1840015695833550", "?U-!Zm:l3D#![=)");
            put("2538312093647326", "?X{?Wg04z>0l5Qc&");
            put("4158634127255442", "7#>%^#<:1Hu8:r'");
            put("3922997111340393", ":]14$p1[3<A;/,&(");
            put("6399761937749426", "&4v*:j");
            put("2754896992342218", "5Ts3:l&=($Hw4D=0");
            put("6048332312871132", "9C?3l+Ro?+,/!");
            put("1757148124391467", "(,$Ae+Aa>Ai?:>0");
            put("2529499690120931", "4Hi+Jy!Py>>4#G!,");
            put("6762585453496975", "?Fy/Cy!Ky;Zq<%");
            put("3469150132968061", "-F}+1v%Cg'),");
            put("8753546815431210", ";N#)J#,<&%I1-Xw&");
            put("5811541119780590", "/z&O/>.00*6!_)5");
            put("3343117810311055", "1Ig2=62:<43|)0");
            put("6636553130839969", "97j.&*4+t.J=7S#<");
            put("4125060055296895", "),d:D'2v*Ha8/b");
            put("3117720508089767", "=*.9K}7*$8X=%,*$");
            put("6174364635528138", "");
            put("2880929314999224", "!>t>9n8:t7M1f&");
            put("9104976440309504", "&%l'Ry!:$$-4;5t;");
            put("5223320301811753", "!%p&J!.K1,]{:I#=");
            put("3931338628279891", "!Ha.;v;*l>_i'R}>");
            put("7224773948808805", "+Y7)L)31t>2<-Fy6");
            put("1000726823498525", ")Tm'Pk7]-$>v4)<9");
            put("3705941326058603", "!.b/,&%+$)/n/=b;");
            put("5586143817559302", "*Y7!>,5^q>C72>h>");
            put("2292708497030388", ";#2<I7%#2");
            put("8516755622340668", "%N{+[e8Xy#9`");
            put("4635099483842917", "=40T/;5~7I{068");
            put("4519559446248727", ".%49H;)Z%0Oi6!`/");
            put("7812994766777641", "6Qy6<204)#b:$n#");
            put("1588947641467362", "/!<=Di3X/C1<G5,");
            put("4294162144027440", ")#x+3r2)z#D#)Ni/");
            put("4997922999590466", "$(>-;|(4($*|1C!8");
            put("1704487679061551", "1.%-t45(<&5169");
            put("7928534804371831", ">V}Lw:<*$=2%0=");
            put("8752645209624771", "<Kq2O#+Vm2/|)Hc&");
            put("4020137204668733", "");
            put("3695449040995787", "$*0%2$z2Ri%:d*");
            put("2528598084314492", "%1*)*>V=)E37I{>");
            put("1766164182455857", ">;n?R5'^o&Kg<Qq*");
            put("9115468725372320", "8!(9B{+Wm#Cw=Tu:");
            put("5822033404843406", "");
            put("6400663543555865", ":,<<By/*v?A11/*");
            put("8164424391655935", "5R{3/2&5<)^)/Bq7");
            put("9902345384357096", "?1`7I51G-0?f(F}:");
            put("4283669858964623", ";K)%I=R/+z614$");
            put("1940377266345655", "1@q#F/?,r*9p.N!9");
            put("7648372362144221", "&Is>+j+!x?Hg/[#5");
            put("8527247907403484", ",+");
            put("5233812586874570", ";Fm67p5#z7;v2Cw>");
            put("6988884361524701", "");
            put("7576203573687099", "52v*&");
            put("1578455356404546", "3+p6I)==t/Z#;)h/");
            put("4871890676933460", "$@?8>,'-");
            put("1352156448376819", "<,$(E/>Na**f'U;");
            put("1353058054183258", ")<>5_s'+n2@-+^=)");
            put("7939027089434647", ")J/5;r#Wo>(2=Yy&");
            put("4645591768905733", "<!$9Di8Qu>]m0Eg&");
            put("7577105179493538", ":Te&).0Sq'64>$44");
            put("6987982755718262", "&-r/]-");
            put("2166676174373382", "#Y%)+8,$:");
            put("5460111494902296", "'0x*?0*F39Re,T%,");
            put("7639356304079831", ".36(4`$Q'$T5,=24");
            put("1941278872152094", "1&x>2lT791*7-r*");
            put("7350806271465811", "7#z'$z(L1");
            put("4057370950936897", "*I#$Nc=Q-,)81*,");
            put("8165325997462374", ".!4=C9,7:,Hm0K=,");
            put("1693995393998735", "/#,1Ay.:~32");
            put("7460663536092909", "8/dR?)'(=R+>'6%");
            put("7692645217087727", ",%*");
            put("4530051731311543", "/16");
            put("7235266233871621", "$9r2@#%T!-'0;<h3");
            put("2056818909746284", "=<$.8>?*0.|3Gs&");
            put("1236616410782629", "/Ve*Ee+$f2F/2#b*");
            put("4987430714527649", "%0&0L/;5p&9j).x&");
            put("1105774576029899", "7V-)g(%04Zs");
            put("8048884354061745", ";D-=8:9R#9N'=Pg7");
            put("7104424399118891", ":Hu.F!(S50Ds;&");
            put("5118272549280380", "&$0)6($'h#Pq8Ne/");
            put("7823487051840458", "+Eo?;&8C#$U/?^}.");
            put("1468598091777448", "%;h2Ng,N=0Nq9Ce/");
            put("1824837228751466", "1Bs7-:+)l[)'V#4");
            put("4399209896558813", "'N7-C#%3n++21<>");
            put("5175537580610630", "'(n/?d6W?9&6>4r/");
            put("8637105172030582", "1M}3&`'Si'<2%*<1");
            put("6516203581150055", ":#h.5n4G+;`$2j");
            put("5706493367249216", "=(l.^g.Cy6,");
            put("8411707869809294", ".<z;C#[{:Ek,Gc+");
            put("8803772738086118", "5#(!Oy;3b&9d=W/0");
            put("2413058046720302", ":&`&#n$!64Yy>$z.");
            put("3810989078589977", "<(>!U'13($C+1E/<");
            put("7066705990777330", "'Y1-?(?Y!<Su6%4!");
            put("9221418083710133", "%_o/2r940=>?*h3");
            put("5927982763181218", "4_}.Ms=:.4+4#C3$");
            put("6294714185218053", ":<0");
            put("8999928687778130", "5/p:D',245Yq)I+");
            put("2921564558397754", "6[y:9~2L-8V9'Ki+");
            put("3001278864689138", "0<.00`?+b*%<?Je");
            put("3222768260621140", "+M/(:>'[k/Jg/8,0");
            put("4046878665874081", ">J)4=r+T3<Hs2Ug;");
            put("5107780264217564", ">.|>X)7#(8_=2*$,");
            put("8401215584746478", "0E+r+]'9C;");
            put("2177168459436198", "&=`+M'=C?(Oq'@c#");
            put("4882382961996276", "(Pw>+~=A?$Tg>W-");
            put("4409702181621629", "0(t7Va:T)9^==D--");
            put("1116266861092715", ";m'6<#J90603#:-");
            put("7340313986402995", ">(<");
            put("3458657847905244", "6>r.Co#O{+-j:G#<");
            put("5696001082186400", "#R7)");
            put("8989436402715314", "6>");
            put("2765389277405034", "('|&0`30");
            put("5470603779965112", "./$0)v>!6)::4F?5");
            put("3821481363652793", "+/j378:(|&8|)L;%");
            put("5280460431238793", "%A9$!,9[+(]{!*=");
            put("6752093168434159", ";HsUo4Q:Ta+96$");
            put("2870437029936408", "5U95,l/2(,O#7_1<");
            put("6284221900155236", "==2$Ma::b'Z?$#h?");
            put("8869086853025400", ".T%9#n9P1$F=6(r2");
            put("3353610095373871", "*X.Fe'K=");
            put("6058824597933949", "0>x.C37J=8@%2H9,");
            put("3233260545683957", ".5,");
            put("6017477484495704", "5By?0h)!4%Se19|:");
            put("6163872350465322", "+Z?0@%;H')Mm8Ec6");
            put("2282216211967572", "%Q5%");
            put("6872442718124073", "4G=$'d.[a:$03*z.");
            put("8280866035056564", "?/<,56)6%m?@m");
            put("3941830913342707", "2M%4Po!(z*E5,U)=");
            put("6647045415902785", "7Nc'8r.T!");
            put("2645039727715120", "#");
            put("6483955928137933", "2Z#!Om::t6]3,M=%");
            put("5575651532496486", "6*j/k,8&-Xi$9<)");
            put("3011771149751955", "+R+0$8!4<=Y).->0");
            put("6280313993865951", "0$5M/:h7_y;M1(");
            put("2986878673337037", "2Z!,;");
            put("9210925798647316", "*$$1<2*;4(/h?Gk?");
            put("6505711296087238", "(Q?%1~.78(4~&3&4");
            put("2648947634004406", "04f#Ei>%=[/=1");
            put("5942382954533320", "%|64f5(z&@c9@-$");
            put("2816641707769592", "#'849t/$h.Jg8`2");
            put("3599991967720791", "2Zm2&<7Bo3V%7I;$");
            put("5692093175897115", "8)*(i$$$9;.%D?(");
            put("2398657855368200", "/=~6N)");
            put("8622704980678480", "8Yo>=4*Y#8Q;-46$");
            put("5917490478118402", ".W5,E+=K!=76-n6");
            put("3237168451973242", ">W/$,81Cs6Xk.#p;");
            put("6530603772502156", "6R1(~!Ky>x");
            put("3065566471918771", "<+");
            put("4188212785689627", "!K{&8<![}*5>5X)");
            put("5103872357928278", "6L{._{6D98?|7$z7");
            put("1810437037399364", ">!*1Xm8Xw344.Jw6");
            put("8034484162709644", "$Ky&7,(6v&%f>Y'");
            put("5329269660149566", "0R;$L'$Jc+U1<1&%");
            put("3825389269942078", "5Og6!0$Zi?4(=;$%");
            put("7118824590470993", ",Ea+%h'0<,6)Se3");
            put("8947774651607134", "'9$-,b.#6-Ps55.!");
            put("4776433603658464", "?$`;@1&Ee>040]}");
            put("4515651539959442", "08)Y5-(f2@k<&~;");
            put("1222216219430528", "&1f6@/.L)!Mu?]i#");
            put("7446263344740807", "85n:1(-&65D;W?");
            put("4741048842180729", "5S34?8*J/)S-<4>)");
            put("4413610087910915", "<@/)=~");
            put("7707045408439829", "1344/n.Ne/Vc=Hi*");
            put("1482998283129549", "-I?%W19^s/5l.]k#");
            put("6588878778766096", "5IuJc/)*1_m.;");
            put("8633197265741296", "/");
            put("5339761945212382", "14$,,t)1d:T+/+,");
            put("6882935003186889", ";6z#'z!^c>Y3+-t3");
            put("8858594567962584", "&Lm2/(8D:Lc4^98");
            put("2960643621290608", "=0d>86,Cm42_/9");
            put("3589499682657975", "+61=x?Oi#+z#Kq*");
            put("2634547442652304", "6:49>");
            put("1247108695845445", "+:");
            put("8044976447772460", ";[/-Pi'J'Sq8Li3");
            put("4751541127243546", "%U!9Lk1W}&O7&1d&");
            put("7471155821155725", "4Ke;Xi+1:4Yc79`.");
            put("8270373749993747", "+M%9C;5Qu2O?,B1$");
            put("8842851800978971", ">Dc7=r1.:83f(Yq3");
            put("4177720500626811", "#G/5L5!Gu2Ck$U/,");
            put("2046326624683468", "*Z{.[c/$,)t?5$<");
            put("1835329513814282", ")Xu3_9,!p3K59/");
            put("7456755629803624", ";I!!'<;@e..*");
            put("4163320309274709", "+g6=f0/r#_q*'p*");
            put("8059376639124562", ",Qs:9n3Tm.O!%<l2");
            put("7682152932024911", ",H%<N{*)~7Ig,Sq2");
            put("1472505998066733", "(Bc.@57Co>{<Aa#");
            put("4765941318595647", "!?*4>=3*,3`&B+(");
            put("1458105806714631", "0U'88x)S=0V'&%p&");
            put("2423550331783118", "7$48),0%hUq4,88");
            put("6868534811834787", "9?j&");
            put("3575099491305873", "+3.$4<,Ii#!v%*");
            put("8647597457093398", "+Eg2&0i#:v?S%0");
            put("7093932114056075", "0Nc;0p?#n*H+=$~.");
            put("2060726816035569", "#Ny'.x%_)-Wg5");
            put("5354162136564484", "-W31#~;648*>3M?)");
            put("8698849887457955", "19((V#/^{'S{-5x.");
            put("7717537693502645", "<@)0567D-8%b4O5<");
            put("1574547450115260", ";2`?>`96.");
            put("1718887870413653", "-#z?<");
            put("4505159254896626", "8D;-*");
            put("1799944752336548", "!Qc6Ic;9b&E%&*.");
            put("7354714177755096", "6-x')<#=8;&<59");
            put("7798594575425540", "/)t68tP'=(<3R=$");
            put("4424102372973731", "53,%Xo'Hq6Zq;5(");
            put("8305758511471482", ".n:Fw*G1)(*");
            put("9863266321464243", "*825'd3.b3!j");
            put("2307108688382489", "8U{3Ka<#$%[+>|2");
            put("3916938436927789", "=Lw/)|4Hm+Ac5");
            put("1211723934367711", "%!6!<2&Cc'E#/6.<");
            put("7942934995723933", "+F/$U#:9j.3v7=.9");
            put("7210373757456704", "..d&G7;_?");
            put("5012323190942567", "$Q==Gw94(0Wo8Uw3");
            put("8893979329440318", "/M+5Sy0Uo+Wo!5<8");
            put("3981058141775879", ".E/1T?)?>");
            put("2895329506351326", "5Sq/X=");
            put("3328717618958953", "");
            put("6235031163988755", "%0x:?v)8>-F!=`;");
            put("8531155813692769", "(]i;3l2Q+");
            put("6622152939487867", "3?(060-&$0]k)Vc3");
            put("5600544008911404", "&?<$2.(f:7*-$&5");
            put("8964543926300396", ",");
            put("1901150037912483", "//`+Zy$5*,(~,U5<");
            put("3483550324320162", "-F'9O?#)v/5f05&-");
            put("2740496800990117", "*Li_'");
            put("3528229843003917", ")Ou:Dq,1n#>#Q{*");
            put("9119376631661606", "6W1$R=2");
            put("6033932121519031", "&Vs&Ga!D#");
            put("6188764826880240", "#Ka:Dk.Gg/Qy!Qa&");
            put("5364654421627300", "");
            put("3927430721990606", "4+n?<l,<d>Aq4[c6");
            put("6339954014616917", "%7tPo*");
            put("6858042526771971", "#^k:@9(%p;.,#Q#(");
            put("4152828024211893", "8/d+%l6&4<&8=%*%");
            put("5001830905879751", "=:l'D)##<4Mq:$r*");
            put("8295266226408665", "/K#09:?8t3U#('(");
            put("2071219101098386", ":5D;");
            put("6511517399130787", "9>|:G+E{/[/-]m;");
            LOG(INFO) << 1;
            put("1573987489603120", "4.f.X%6+z?4:&<,5");
            put("3916938436927789", ");z&=2>Lk;;<,G))");
            put("2056040634016302", ")1f+V}.B34N'9:~3");
            put("8411147909297154", ";B51E1188:*");
            put("1106334536542039", "");
            put("8421080233847829", ",Ss.=r/O'8'");
            put("3232482269953974", ":B#%W);O1,Nc5D}:");
            put("3237168451973242", "$P%8E;-T{#Mm1Ls");
            put("5600544008911404", "!]9%%>,%x6");
            put("6410035907594400", ",*r!66<");
            put("2639575269965870", "(*z2+f+Z?<^'!+$,");
            put("7695234182336898", ">[o7|<Z+%+x]-0");
            put("6983296573698995", "1Vc3Ug/)$,%*;_e2");
            put("1955337418209897", ",A#5;n.Ha&Te9-5");
            put("3227796087934707", "'G?,38(]k3G)*Wk3");
            put("2408371864701034", ".N/-,z6*j;M75.z");
            put("5711179549268484", "1(~*<*4L-5]m<=z+");
            put("5937696772514052", "!t6!8%7l7Ao5'&");
            put("5942382954533320", ":W.D{#T7=28^y'");
            put("5691533215384974", "+>nAg;Do2M/6+v'");
            put("5364654421627300", "0%b'I%*T#9M%?,v'");
            put("5817347222824138", ";Mu'R=<Bs>'.;3>");
            put("6048550628088974", ")Zq#;2&U%9(2/3,!");
            put("7592494483887154", "$7");
            put("5329829620661706", "0548*d32n:4f4<$,");
            put("7354714177755096", "'$;h*Kq;I#;7,");
            put("7210373757456704", "!/1Ay-Hy3#3,|*");
            put("1950091275678489", "'O'4B5(C%)*h-5$=");
            put("8165325997462374", "6-");
            put("2417744228739570", "?,3&?B}/Z)1M)<");
            put("5223880262323894", "0/p2=1A%5=,9l?");
            put("8502137115770724", "/Di?8t>-j+Ko,:|?");
            put("6968678067129051", "$Js#|#Xq/.p,7r*");
            put("6862728708791239", ":Wi?Ew(3x2)b%38");
            put("6762585453496975", "&Z9):|9Q/");
            put("8637883447760564", "+5h>'v>3$5Ne;Ey+");
            put("6169460138291029", ")Zi&Ce");
            put("5223320301811753", "9't>9829`36d.<%");
            put("7466469639136458", "3Hu7&t4)&=N5!F'8");
            put("3599432007208650", "?Pg.7r.=r(v<K'1");
            put("8749128160593618", "-D%!]!-[?*7Ma/");
            put("6862728708791239", "3O;?j7S39F#)~6");
            put("8947774651607134", "1Ck+#h!Q}:0:!");
            put("7104206083901049", "#&r?)0=8x2+r=I};");
            put("2644821412497278", "(=*%Z74Ru`*^c#");
            LOG(INFO) << 101;
            put("2408371864701034", ">@m*P{+*<5:z");
            put("2156962165040548", "8C!(?b494<Qs8@e7");
            put("5181137185732034", "?3*=**9Gu6)h#8,");
            put("7572077352179971", "81.4Wk$.:<I;*Pu:");
            put("5122958731299648", "-Fk#.p61<<[k&H)5");
            put("1101088394010631", ",Ew&$*7.(%M1)K78");
            put("1000385178204227", ")3t&R{.$z6Ww3_+9");
            put("3826167545672061", "9");
            put("6978610391679727", "8%6=@76[q#y4Ow'");
            put("1352156448376819", "8!<%/b='~6-$&_3)");
            put("8044198172042478", "8Sw*Hi$Ly/Ui?=&,");
            put("7817899264014751", "%Qo?T=O}26?P?0");
            put("8531715774204910", "#^=");
            put("5933010590494785", "?*69#d?Yw2N)'S=$");
            put("5817347222824138", "9Mk3J%#N'9Hc.Oa");
            put("4121643602353910", "$K-");
            put("7695234182336898", "49z3>,0+$9Jg>X.");
            put("7817899264014751", "#Mi7X5-8*(-<084,");
            put("5692093175897115", "'2v>1(3_s:4j.M=-");
            put("3464245635730951", "(]{;0.1!t/M{)Hi");
            put("5932668945200486", "%)$)<<2[w+B#?/x3");
            put("1940718911639954", "2Fk>$:.,p?-2<~/");
            put("4891195365522671", "(59;24#>0Za#V1(");
            put("8034484162709644", "8X'0<|?/*");
            put("7817899264014751", ",8>");
            put("8521783449654234", "6]c2*82#b/B?&$.%");
            put("7244638597910157", "/$*-4&<Oi;Cu%Aa;");
            put("4153387984724034", "(Di;#t*08918,/");
            put("1573987489603120", "89j'Ly3%r+($)^%=");
            put("6635740598958773", ".<`?:*#Q!4~4");
            put("4121643602353910", "(%n+.v=T9%^'++&(");
            put("2745182983009384", "%1h2[)(Gk;J75Qa;");
            put("9221418083710133", "*3v?Qm.-8,%x<#.9");
            put("3237946727703224", "-T)9=n84n.10)Lo3");
            put("1482998283129549", ";Mw3R?,$~#J99%4");
            put("6284781860667377", ";A+");
            put("5364654421627300", "/(~_39L{>E#&9.<");
            put("6289686357904486", "2>><Ms$3,(Vo>-1");
            put("5827061232156972", "*58818$E{1&>M!=");
            put("6415282050125808", "4D!");
            put("5460329810120138", "-P'-3t#0%T-%4h?");
            put("6583279173644691", "2J'(0`/P'%!>;[q>");
            put("4775873643146323", "8<p+Q71Fi?M}?K7<");
            put("5514694753139079", ".W!$?v.K-<2t&Hi>");
            put("1231930228763362", "'");
            put("5917490478118402", "!B7-^%6To/0b!10=");
            put("8512069440321400", "1;.4T#*$$");
            put("2644821412497278", "7O;(#x?8b&*$;!p&");
            LOG(INFO) << 201;
            put("8049102669279587", ",FiT?=l:I7/P;9");
            put("2528598084314492", "?X}:H+W/,Sm)I75");
            put("4177720500626811", "*Q/,Kk:7`/T#8B}");
            put("1342784084338284", "85|:Vu48n2Ce/P#-");
            put("5817347222824138", ")!n/To?Qg>Y3=.8");
            put("6174364635528138", "&SaUq)Ek28(>_c/");
            put("5595857826892136", ",Bi6F/");
            put("9004054909285258", "!O5)8j)S7");
            put("1357184275690385", ">(,");
            put("1709515506375118", "23n*+:!6x*1878&-");
            put("1578673671622387", ";N)");
            put("8633197265741296", "Gm25v?;<,2b80l&");
            put("8526469631673501", "#?2$Hc6Q%-s<Ui?");
            put("4152828024211893", "%/&4E/*9~3^};<~;");
            put("7702359226420561", "");
            put("9210925798647316", "5)`*.6;F#)/07]+,");
            put("2166676174373382", "9N}'?`+/r#N5/U3)");
            put("6636553130839969", "8Wi/V/!>()O90Dw>");
            put("1352156448376819", ">!$%1~8T3=9z-K+");
            put("3575099491305873", ":>h!r:Oa:'z7(48");
            put("5103094082198296", "=<>(Oc2't8079:<");
            put("4153387984724034", "4!41Yk'Q),_w?/r.");
            put("7596409868082749", "-Si?Ay(44-Jq))<");
            put("3916938436927789", "2(r2O72Q;(.b4Ly7");
            put("2282216211967572", "(,*<^+9_y32%?|?");
            put("5817347222824138", "&H#(&*.S{#F9Gm&");
            put("5937696772514052", ")+j#+`5X{&M31Cu:");
            put("6159186168446054", "*B/(/");
            put("5007637008923300", "5,;5]3,N=%#|/");
            put("3218082078601873", "");
            put("1573987489603120", "*M31&<;[;$$6/<|6");
            put("5108340224729704", ">r<f';r.;x>W/8");
            put("8874114680338966", "-.v2U+?A7");
            put("1573987489603120", "6<d*<07B)4&60M-8");
            put("3358296277393138", ">K=0@='Lg/H3*");
            put("6983856534211135", "(0,%%0;Oc*/r0H;$");
            put("6737474661864215", "(E;,Ne-Q+8Q3?04,");
            put("3348022307548164", "%(|&Si5;t>So=Wg");
            put("2755675268072201", "$");
            put("3826167545672061", "");
            put("1231588583469063", "=[=(8v89,5$.>I}#");
            put("6987982755718262", "5Z;(<d<74*r7)*)");
            put("7089245932036807", "$T)=?v>R)=!(%36,");
            put("6053236810108242", "*Vo#=f5U?8X9')61");
            put("6521231408463621", "/52(?&:S}/#`7Bu:");
            put("3714753729584998", "%2p#F-=Eq7?h9%f>");
            put("3826167545672061", "1,r7A7$Y!=G13Sw?");
            put("2991564855356304", ">(&4Sg7<j#%j!>|?");
            put("8290580044389398", "#B{*R1(s+)&%6<$");
            put("2816641707769592", ",3$8>r=76-Tc7Y}*");
            put("8421080233847829", "2)l2!:&'4<|;?l+");
            put("8054348811810995", ">)n7?40[o?Qu");
            put("7460663536092909", "4&-%l>(*80.2?<");
            put("1694555354510876", "1:4");
            put("5460329810120138", "8N-![13F?%1b*N!,");
            LOG(INFO) << 301;
            put("4736362660161462", "'4%K-7T+0Ec>:j2");
            put("1573987489603120", "!Tm25$%N'Q170b>");
            put("1116266861092715", "=N9%Be6^gP=K+,");
            put("8305758511471482", "+E;-%h9U1<I93Mu&");
            put("8893979329440318", "?:p:_c-<p6=2,Yq");
            put("1603566148037305", "%p&-$,!x6I1+Cu.");
            put("5817347222824138", "69f&7");
            put("7354714177755096", ".L}:8p!%4%Bg4')");
            put("6405349725575133", "59|:Ge$:0!0d1/*9");
            put("4389837532520278", "*`#60B3.6]{>");
            put("8853908385943316", "54l:H;(343>-?<$");
            put("5811541119780590", "%2rF3/Yu6H/*V!=");
            put("6867756536104805", "1^!-&80S'<.8#6,(");
            put("5811541119780590", "7%j?1z,!h+V'.=(,");
            put("2865750847917140", ",Oa+^m)Z50Em?Is'");
            put("3348022307548164", "/(f.Ze&M==6:(Z5<");
            put("2292490181812546", "1=$->6)Z5-?~%%j/");
            put("2056818909746284", ">9n#W#[y&2z)<(<");
            put("1487684465148817", "9Ek?Sc?Uq?R+0>(");
            put("3468931817750219", "%/x2M'/Zc&Y/5`2");
            put("8984408575401748", "&Em'*$*A)%Dm1Cm3");
            put("1598320005505897", "$/p3Y76R=$=<!?&!");
            put("5942382954533320", "%3l2");
            put("4389837532520278", "@#<G%4|:(x.M=1");
            put("3695667356213629", "2Eo:?|<A3%F?2Ai#");
            put("9105318085603802", "4Xw3N724l672<+$$");
            put("3454531626398117", "$Va3>b&]--:`2");
            put("6757120995747725", "2:|>L<B;13v)64(");
            put("3222768260621140", "");
            put("4047438626386221", "!K59T;.1");
            put("2171580671610491", ":$t6;,(,j#C'8Iy*");
            put("5912804296099134", ">024Cy4Ck/O=,V%1");
            put("6149253843895379", "$Mm/Vk2D.Qa<2h?");
            put("4997144723860483", "9#0,.0(Xa?");
            put("1473065958578873", "(<44=6>.2!#x!7t'");
            put("4173034318607543", "!Si+B7-2:9:$##l");
            put("4741048842180729", "2=fMu359-<8Cg+");
            put("7827613273347585", ".V));f;Zo;L;&X90");
            put("1805750855380096", "%^7%@7.!$5W):Va?");
            put("1573987489603120", ";D{;%9>*0");
            put("8049102669279587", "<>~*'<.V'8O)'Vy*");
            put("3237728412485383", "!O'(R?");
            put("8285552217075831", "");
            put("6483955928137933", "");
            put("1362430418221793", "?Xi64,98.(*21<88");
            put("2307108688382489", "6Vi#,*;H)");
            put("4630413301823649", "0%d/.j&Nm2Dg++z:");
            put("3222768260621140", ",!<9'p30$Ni%M+(");
            put("6525917590482889", "%Rs+Iy.,(&x7I5=");
            LOG(INFO) << 401;
            put("2533625911628058", "4Pa/3&,=,)9");
            put("1361870457709653", "0T)$Fu.X91&:;Q{");
            put("2538872054159466", "3=v?Ck/Ou'Pu");
            put("1710286304198790", "'9l7Pc.(b2H=:L!%");
            put("1573987489603120", "-K+$Qo,?>!='Xs:");
            put("8391501575413644", ";&48Xs4.~>@92440");
            put("8869086853025400", "Eu7<>*|?S;3W{?");
            put("6410035907594400", "!,r+&j;N%<J:(v#");
            put("7330941622364460", "><24Oo-'v3%:25:<");
            put("2745182983009384", "#8:1=$&1,");
            put("1699801497042284", ";O94Eq4/l+J}3Is3");
            put("4172692673313245", "<-|:502Vq:[a8");
            put("6622152939487867", "9<-{)Ie;Mw/D)0");
            put("1684623029960200", ";Fo?%|-Kw6#x'Fe?");
            put("6651171637409912", "0Ck*#.=Xq'V%.-|");
            put("7345901774228702", "1o;Za#p:6-e.");
            put("6284781860667377", "<)*(K1;5l>/()6<!");
            put("5942382954533320", ")?|3U)*]y.!,-9n2");
            put("5223880262323894", "5607");
            put("5460111494902296", ">8l;74/=$%764(,");
            put("8753546815431210", "##(1/03Ga#!0Bk;");
            put("4171921875489572", ",S)0(v7]50Tq'R/$");
            put("5933010590494785", ">141/~)8884$0Hs");
            put("4770627500614915", ",R{3D5=(");
            put("2171580671610491", ";]}35f6;*,Wa+%v.");
            put("4153387984724034", "9Va&:");
            put("5122958731299648", "=X'");
            put("8507383258302132", "&Ey/08*(x&$09F-1");
            put("3916938436927789", "(*|'b*N9=#d>',-");
            put("6631525303526403", ">A9(/p%6b#O}&+21");
            put("5918050438630543", "<4r:V7++d#+43Dg2");
            put("6525917590482889", "<S=5]w5(.1Ce9&l7");
            put("4635099483842917", ",B11?d;4)O?)1t/");
            put("5817347222824138", "*7x+>d.+,2b;;:8");
            put("8748518988117644", "!w7=b?^9=R}/D{?");
            put("5107998579435405", "%N941`1<l+6");
            put("4530051731311543", "97`/?d43f'.<.=$%");
            put("8632978950523454", "0Ag#@w8L!8W-!',$");
            put("7711731590459097", "710)+?^5%D/>P/");
            put("2755115307560060", "3'b;Z%/>,,,x8!z2");
            put("6433677655002271", "9$f>&r=!t#>v.Iq#");
            put("4273955849631789", "=48%5v)Qe/<|!80%");
            put("2649725909734388", ",!x>,&");
            put("2162208307571956", "8U7(E-5B1)1<93h?");
            put("7350027995735829", "!Fo3)t/Q;<");
            put("8874114680338966", "89~.6$(Yc#U++H7$");
            put("1718887870413653", "6Z/8");
            put("5807414898273462", "'[7)$&:?f3]{80");
            put("2996592682669871", "(Tg*Rw;:2)0f-T'-");
            LOG(INFO) << 501;
            put("5586143817559302", "#Kk6I)#-4$To#+`#");
            put("2297736324343954", "9?2");
            put("4997922999590466", "-[y'X=?Q1!>|;$0-");
            put("6284781860667377", "1<f7-8<k6;0/F7%");
            put("6159186168446054", "0I?88d55p&4z70n#");
            put("2648947634004406", "2D-$'~05x6D'5R=8");
            put("1357744236202526", ")#>5(2((*1+n;O%5");
            put("7582009676730647", "0=");
            put("1372362742772469", "5<r.U#&H')E7?B}.");
            put("1573987489603120", "+D3=+Lm;R?!Oe&");
            put("4288574356201733", "='2,,n;7(0.b;5$$");
            put("6747406986414891", "9%5K:[-!%~6A}2");
            put("3237168451973242", "+@94-*/8<,0876<");
            put("1573987489603120", "*B)$;h.#.='`!<0$");
            put("8405901766765746", ">/8!0x<&(-Vm#<");
            put("5802168755742054", ":w*5v,1b:=>=.n+");
            put("6521231408463621", "64l6$?9,5$*)74<");
            put("1347470266357551", "$[>!*!Tw;>0#(8");
            put("8526469631673501", "+Ty*Gi4W+)-r+/f;");
            put("5942382954533320", "8^qQ52Ag:2");
            put("2272843847929036", "1r7G/<M59Y709$8");
            put("5817347222824138", "<E91/:#*p']c7+|&");
            put("3705381365546463", "5$`*_9&8l;Ci");
            put("6993788858761811", "(:t2Du:W?4U=(/,=");
            put("7689634577215493", "%(.-=6!#x6%z#M'(");
            put("4645373453687891", ")By:Y'Ou*42=D9!");
            put("8421080233847829", "6*<-");
            put("7224992264026647", "5;v/>>7^c3N52Q/%");
            put("4177720500626811", ")5r#K#!Lq*<r?W#$");
            put("4273955849631789", ">Eq7Cg*Og2R9");
            put("2639575269965870", "!&.)P'&[/=P#@i2");
            put("3916938436927789", "%':88x)c(266");
            put("7330941622364460", "%Ug>5*'81Qw-X71");
            put("4891195365522671", "'6b'K{;Pa+X5%>h:");
            put("1372362742772469", "$Dq&3r&B+0(602v'");
            put("2408371864701034", "8G!57$;80");
            put("4298288365534567", "+U58Ug=s3;84+r:");
            put("4153387984724034", "!&$(*(%05V5!Uo3");
            put("5113244721966814", "82t3*f,M{+Qy6T{#");
            put("6873220993854055", "=Tq*M'<H}>Q?>(,9");
            put("3690421213682221", "1;(,Io3_))Vi#+t/");
            put("6483955928137933", "2#.9*h:&(5");
            put("5696779357916382", "/1>=:j?Jo/:0-T}3");
            put("2986878673337037", "&>2%Ny)S1=;rK)(");
            put("3242974555016791", "2_m6&f>E50:>:_}2");
            LOG(INFO) << 601;
            put("4997144723860483", "68t.!f5V99&'@m6");
            put("5831747414176240", "2A9!&p'[;4*$?K%9");
            put("2292708497030388", "0*)Vu=Z!$+tW7-");
            put("1573987489603120", "0@g'Vq3=d>Uy");
            put("5932668945200486", ",'&-(j9/f/(6;f6");
            put("4298848326046707", "8+:85");
            put("8029797980690376", ",Im:'h+Ko?S%%=f'");
            put("5214507898285358", "=K55Ce,P/!W1!D'<");
            put("4399209896558813", "*Gw20`8Co-8>7x+");
            put("1699801497042284", "1,");
            put("3464463950948793", "<Go*M}9->,Lo0Bs6");
            put("2982192491317769", "9,,");
            put("8652283639112666", "6)d?1d<Bs+;$1]=<");
            put("3528229843003917", "!Ai*Gc>>t+%f/^9<");
            put("4882382961996276", "9!<=<6Z{?_10S/0");
            put("3695449040995787", "!]+%G;*3>");
            put("3685735031662953", ":De'U%-L-=0lY;5");
            put("7689634577215493", "%:>8C10_iB}%#2=");
            put("6862728708791239", "(@=0,t8Ok#E?.^)$");
            put("9004054909285258", "*;.5>6.U!$8r/'");
            put("1573987489603120", "*Ok.N'7K}*0<9'.%");
            put("5932668945200486", "6t*Wc->h6Hg'A:");
            put("2639233624671572", "9?,$;f$Y-$=x7E1!");
            put("5514694753139079", "!$b'V2D=0M#,3t?");
            put("3343336125528896", "99t/$r?T3<(7");
            put("5585583857047162", "!^)1,f");
            put("5817347222824138", "%:.$$8&");
            put("6017477484495704", "5_38Hy%O?-.*v.");
            put("6410035907594400", "-7f*Xe.-<W=?N>");
            put("4394523714539545", "=])('v;Ui'#,0Nc?");
            put("4866862849619894", "L/==l7I7W;E3)");
            put("7104424399118891", "#Ya+W-7161=05.n.");
            put("9104976440309504", "2;d#^q:<v3@31Ju3");
            put("5570965350477218", "7%d#.v-$z?Q-L',");
            put("1573987489603120", "4];1)x(A'0+-&");
            put("5942382954533320", "6$x6$<;6)No8H15");
            put("1347251951139709", "7,00T'7Z9$$|(($%");
            put("5107998579435405", "0*r>U}.>~#Yi#%x&");
            put("6159186168446054", "5I7-/f0J}#Eo8Xa>");
            put("1955337418209897", "+V%10l3!z2527[g?");
            put("1573987489603120", "4+`'V=*_+8=v1f:");
            put("7822927091328317", "6.,!3h&<j/J/!Mc;");
            put("4414170048423055", "4J'0500Z3$-$:*(");
            put("5715865731287752", "26h2J:Li/k0");
            put("6053018494890400", ">Rc3Zc0)v'[/J5)");
            put("1573987489603120", "#Q{?%>=z?Ay-R/,");
            put("7742096002529574", "");
            put("7697673044401294", "8&.%'8?64$Rw>4>");
            put("4756568954557112", "9/*)Ay>H-");
            put("5548859282568936", "5Gy&@y9&(9S=5Ms:");
            put("5327322251431469", ":M6S'%*4,Ow?@q+");
            put("2408371864701034", "'_3-/p>3:)F;4@m7");
            put("5213947937773218", "%$)");
            put("5937696772514052", "42p.+&.*%;r6,j:");
            put("3458657847905244", "9#2<7h1S'1]o+I+9");
            put("7803280757444808", ">Ha/9n4>6)R#");
            put("7841419248036332", "9Q%==");
            put("7010709939563285", "");
            put("2519225720275956", ",!l#Ci%Do>;<>H%1");
            LOG(INFO) << 701;
            put("1573987489603120", ")39+$?['8Go#;*(");
            put("8049444314573886", "");
            put("8753205170136912", ">S{/8$%_g3+8+R};");
            put("4997144723860483", "<@s*!r$(0=9v$-f#");
            put("3227454442640408", "2Iq&Qq.Y1=4`0=");
            put("1574547450115260", "2%9!v-/:8O#4Ye>");
            put("2861064665897873", "0O?5-#]7(7`0Z%!");
            put("9210925798647316", "6*,,_}:$&0@+(Ak:");
            put("2156962165040548", ".-z.@12Z+0,d*X7");
            put("6862728708791239", "5So&&0*_9");
            put("6756779350453426", ">E9(Ps484(.&!0=");
            put("8878800862358234", "1Tc.8r.V;=*");
            put("5223880262323894", "%!f75t*8x;3$.-p?");
            put("5103094082198296", ";%p+4r3@5!'t*Tw#");
            put("1699583181824442", "<.v3(j+'j7S+++40");
            put("2759801489579328", "");
            put("3806302896570709", "O)<Su(0d*6()-j+");
            put("5817347222824138", "?G/=9l,'|*Kw0,j>");
            put("2996592682669871", "^39Pc2=h33,3Go;");
            put("3599432007208650", "7Ui9h-=2(=,(L31");
            put("4152828024211893", ",:p#;,0721'j%Gu'");
            put("2760361450091468", "+)<=:f&4-[19Hk#");
            put("8044198172042478", "05j/3:1)p.>.L)8");
            put("7350587956247969", "5");
            put("6521231408463621", "<22$>.!S?1*2;~>");
            put("8647597457093398", "");
            put("8164984352168075", "%D}:Bo;8$8,2=M)<");
            put("7109452226432457", "&?v7Ey9+6<");
            put("7682712892537052", "*Wy/Km$)");
            put("9220858123197992", "#I)1;%!f;q)_78");
            put("2288022315011120", ":Zu?He:'|/]o");
            put("1472505998066733", "Xq;F;<,t?*p5S/=");
            put("5580337714515754", "(8f?7,.]%-L{7>0");
            put("4052466453699787", ";5f>A=9!|#3t0I{");
            put("5081813940225276", "+Ti&,b!6`+Og,!r");
            put("5329269660149566", ">`.1*+]!%Pg:4r#");
            put("3700353538232897", "$Pe'S=7!<-)2Xs");
            put("7812994766777641", "");
            put("1458105806714631", "5.$0Bm8^?5?:7/n7");
            put("8795989980786295", "8Hs/8");
            put("5575651532496486", "+0j*:(+/x+*4/S/8");
            LOG(INFO) << 801;
            put("7788957822722251", "9$p2.%9$");
            put("4288574356201733", "");
            put("1472505998066733", ",I?$Q%,5");
            put("2770075459424302", "&Yi.U)5Qm6.2>)<,");
            put("9119376631661606", "");
            put("2408371864701034", "<U}6@):A-");
            put("4153387984724034", "/_y6");
            put("1096402211991364", "9^y3J1,B),Ii1S)1");
            put("3121846729596894", "0Qm?1r-Wu/10?*($");
            put("1472505998066733", "(f2--8d:O>/r;");
            put("1760564577334453", "#z6C9!@-$3r4(x.");
            put("6862728708791239", ">Q}&Om90$4-(H%,");
            put("1468038131265307", "'F5)Oo?Lc*!z).n>");
            put("5817347222824138", "'S=(J{!!l;/|$4<");
            put("3584813500638707", "*4");
            put("3916938436927789", "?9bQ;8=");
            put("1941278872152094", "-Uu.Io$_3(<j>Es;");
            put("6053018494890400", "-,v/&(8c#Ig7E{+");
            put("4650619596219299", "*(b'6l3/l.#0<Co3");
            put("7460881851310751", "9V=4=(7s?2><Cu7");
            put("3362982459412406", "+,j>[#1S}:F)2Tc>");
            put("6987982755718262", "7H%9");
            put("7210373757456704", "7X31(+/4");
            put("3112428292111447", "-E7,B+1#h6$Js#");
            put("5586143817559302", "*@i?T}#[7=Nc3E{7");
            put("6535289954521424", "6R9)S?6'4,?b<1$");
            put("9105318085603802", "?'04P=89x*Le<1*)");
            put("8049102669279587", "3!z/Oi#Q!");
            put("3338649943509629", "<=8<R7T{*Oo+,0%");
            put("4153387984724034", "'_3)K{%L!$+$#6j+");
            put("7827613273347585", "9J?8g2>0!=r6Eo6");
            put("1824837228751466", "7,j:]i#Fw'Aw994%");
            put("6968678067129051", ":@7-?");
            put("7582009676730647", "89d6F)9C5,As:4&$");
            put("3222768260621140", "1:4,D+'1v#I?99l6");
            put("4022320356847152", "=<.%>b-C?9+h>^a'");
            put("1694555354510876", ";D'$3&");
            put("5335075763193114", "+Os:H+;Zo>.v:;&5");
            put("3931338628279891", ".A#!Kc,05K9:-l3");
            put("7566831209648563", "&2`L}9F1<D#!$`6");
            put("6858042526771971", "2;x;<`3*.5Y'");
            put("6867756536104805", ":%$0O!,'6)E+#2><");
            put("1573987489603120", ",!$<n$.jK{0Vc:");
            put("1906749643033888", "02`7>h=R/1(d8De.");
            put("8044198172042478", "");
            put("8947774651607134", "&_y+::6Lk>W;-&$");
            put("5711179549268484", "*C#8<9^c*'|");
            put("5807414898273462", "4@%");
            put("5460329810120138", ")C/(7t)6($:,0()");
            put("2277530029948304", "<>x>6r=:z:<j8?<");
            put("9100290258290236", "4'0$");
            put("2880710999781382", "9]}?(d2C?");
            LOG(INFO) << 901;
            put("3826167545672061", "3@'$8*;E{:L}2Dq/");
            put("6048332312871132", "N{3Gc:W9=^';55");
            put("5470603779965112", "+$006|,Nk?Bc71.)");
            put("6168900177778888", "-F;=F19'|##h8");
            put("1824837228751466", "2-,$R}Q+=0d+V)=");
            put("5797482573722787", "3?2!4l4F+890,Li'");
            put("1573987489603120", "<N}/Uo:+b&0~=;.4");
            put("1101088394010631", "$&5Dg(,6)22?E-$");
            put("1693995393998735", "$Y)4Em#Au&`8#((");
            put("1573987489603120", "5u>,n#*=%z'Yq#");
            put("9110564228135211", "5I+1<$##n&Mo'Pa&");
            put("2282776172479712", "'Z74<r/]s2]3Iy;");
            put("5330738704374455", "6,x.=~)0,5Gy9P1(");
            put("4302974547553835", "=Y;%Vs'Ac:70N)-");
            put("2880710999781382", "7Sc'&>0Vk;Ja>.f?");
            put("1105774576029899", "3/01I{$Oa;Gu*#~?");
            put("1709515506375118", "(7r6&8+>r60x<$.,");
            put("6285000175885219", "3'04Os=9f6T9$^3$");
            put("7717537693502645", ",Lq7&j3Ak>Au/$1");
            put("6178832502329564", "+>`/>40J'9Q1(/l'");
            put("2759801489579328", "$L9(*|+,<C)-',5");
            put("6987982755718262", "<Xo*(($E'1(d;%68");
            put("5455083667588730", "!A%t91`?T?/@k6");
            put("5108558539947546", ":E!=");
            put("8054348811810995", "#/x#.09T=1Y-+$,");
            put("6622152939487867", ">2r6$z0a+S;.W}2");
            put("4997144723860483", "Q)$,<6'h+7:=:*$");
            put("9210925798647316", "3Ng3..#/j'Go>Yy#");
            put("7093932114056075", "9,p#$b+D{2Xw8T}?");
            put("3816016905903543", ",]7)<>(G/43x");
            put("1458105806714631", "6E+=7,<W&Zg-_=<");
            put("7596409868082749", "=KuA18H)0.l/J75");
            put("4027919961968556", ".)*");
            put("1111580679073447", "0Vc'%8<U7-?f+J%-");
            put("1116048545874873", "$!(S%8M;%#z!H#)");
            put("6767053320298401", "<");
            put("1931004902307120", "2M5)Bi-K)");
            put("8753546815431210", "$A)57.,@%=We;V{'");
            put("4982744532508382", "3V?9Dy7^;<]e#!81");
            put("3474177960281627", ",A756");
            put("8854468346455457", ";)z+V'=4$");
            put("1573987489603120", ";54=2p4?(8#&([{:");
            put("1573987489603120", "0#p?[c)-*%u?34=");
            put("5122958731299648", ">3:$0f59x39n*R/0");
            put("7089245932036807", ")Kk7$2:Ne2_c#_-(");
            put("6641239312859236", "%<^u4;$%?f<7r#");
            put("3695667356213629", ";!x7n)D?1M3*Jy:");
            put("4525023903997977", "7G=46<0RE;/=x7");
        }
    };

    TrustedApplication *BuildTrustedApplication() { return new HelloApplication; }

}  // namespace asylo