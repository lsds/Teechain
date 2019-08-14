######## SGX SDK Settings ########
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SIM
SGX_ARCH ?= x64

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
	$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
	SGX_COMMON_CFLAGS += -O0 -g
else
	SGX_COMMON_CFLAGS += -O2 -DNDEBUG
endif

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
#	SGX_COMMON_CFLAGS += -DSGX_ATTEST
endif

Crypto_Library_Name := sgx_tcrypto

teechain_Cpp_Files := $(shell find trusted/ -type f -name '*.cpp')
teechain_C_Files := $(shell find trusted/ -type f -name '*.c')
teechain_Include_Paths := -IInclude -Itrusted -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I$(SGX_SDK)/include/stdc++ -Itrusted/ -Itrusted/libs/ -Itrusted/libs/bitcoin -Itrusted/libs/bitcoin/config -Itrusted/libs/bitcoin/univalue/include -Itrusted/libs/bitcoin/secp256k1/ -Itrusted/libs/bitcoin/secp256k1/include/ -Itrusted/libs/ -Itrusted/libs/remote_attestation

Flags_Just_For_C := -Wno-implicit-function-declaration -std=c11
Common_C_Cpp_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(teechain_Include_Paths) -fno-builtin-printf -I. -DINTEL_SGX_ENV -DHAVE_CONFIG_H -Wreturn-type -Wextra 
teechain_C_Flags := $(Flags_Just_For_C) $(Common_C_Cpp_Flags)
teechain_Cpp_Flags :=  $(Common_C_Cpp_Flags) -std=c++11 -nostdinc++ -fno-builtin-printf -I.

teechain_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
    -Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive -Wl,--allow-multiple-definition \
    -Wl,--start-group -Ltrusted/libs/mbedtls -lmbedtls_sgx_t -lsgx_tstdc -lsgx_tstdcxx -lsgx_tkey_exchange -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
    -Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
    -Wl,--defsym,__ImageBase=0 \
    -Wl,--version-script=trusted/teechain.lds \

teechain_Cpp_Objects := $(teechain_Cpp_Files:.cpp=.o)
teechain_C_Objects := $(teechain_C_Files:.c=.o)

ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_RELEASE
endif
endif
endif


.PHONY: all run

ifeq ($(Build_Mode), HW_RELEASE)
all: teechain.so
	@echo "Build enclave teechain.so  [$(Build_Mode)|$(SGX_ARCH)] success!"
	@echo
	@echo "*********************************************************************************************************************************************************"
	@echo "PLEASE NOTE: In this mode, please sign the teechain.so first using Two Step Sign mechanism before you run the app to launch and access the enclave."
	@echo "*********************************************************************************************************************************************************"
	@echo 


else
all: teechain.signed.so
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/app
	@echo "RUN  =>  app [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif


######## teechain Objects ########

trusted/teechain_t.c: $(SGX_EDGER8R) ./trusted/teechain.edl
	@cd ./trusted && $(SGX_EDGER8R) --trusted ../trusted/teechain.edl --search-path ../trusted --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

trusted/teechain_t.o: ./trusted/teechain_t.c
	$(CC) $(teechain_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

trusted/%.o: trusted/%.cpp
	$(CXX) $(teechain_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

trusted/%.o: trusted/%.c
	$(CC) $(teechain_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

teechain.so: trusted/teechain_t.o $(teechain_Cpp_Objects) $(teechain_C_Objects)
	$(CXX) $^ -o $@ $(teechain_Link_Flags)
	@echo "LINK =>  $@"

teechain.signed.so: teechain.so
	$(SGX_ENCLAVE_SIGNER) sign -key teechain_private.pem -enclave teechain.so -out $@ -config trusted/teechain.config.xml
	@echo "SIGN =>  $@"
clean:
	@rm -f teechain.* trusted/teechain_t.* $(teechain_Cpp_Objects) $(teechain_C_Objects)
