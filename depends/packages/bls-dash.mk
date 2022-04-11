package=bls-dash
$(package)_version=1.2.3
$(package)_download_path=https://github.com/dashpay/bls-signatures/archive
$(package)_download_file=$($(package)_version).tar.gz
$(package)_file_name=$(package)-$($(package)_download_file)
$(package)_build_subdir=build
$(package)_sha256_hash=65a6f5385861e6c5f52bc67518b9468f65b3f826dc9a30cf6e30860e6f1918ec
$(package)_dependencies=gmp cmake
$(package)_darwin_triplet=x86_64-apple-darwin19

$(package)_sodium_version=97b0f4eff964f4ddaf0d0dd2bc5735df7cbd0c85
$(package)_sodium_download_path=https://github.com/Frank-GER/libsodium-cmake/archive
$(package)_sodium_download_file=$($(package)_sodium_version).tar.gz
$(package)_sodium_file_name=sodium-$($(package)_sodium_download_file)
$(package)_sodium_build_subdir=sodium
$(package)_sodium_sha256_hash=151d927c8e49dd290b92572f86642d624d0bc0ebbeb3d83866f35b05f43118a7

$(package)_relic_version=aecdcae7956f542fbee2392c1f0feb0a8ac41dc5
$(package)_relic_download_path=https://github.com/relic-toolkit/relic/archive
$(package)_relic_download_file=$($(package)_relic_version).tar.gz
$(package)_relic_file_name=relic-$($(package)_relic_download_file)
$(package)_relic_build_subdir=relic
$(package)_relic_sha256_hash=f2de6ebdc9def7077f56c83c8b06f4da5bacc36b709514bd550a92a149e9fa1d

$(package)_extra_sources  = $($(package)_sodium_file_name)
$(package)_extra_sources += $($(package)_relic_file_name)

define $(package)_fetch_cmds
$(call fetch_file,$(package),$($(package)_download_path),$($(package)_download_file),$($(package)_file_name),$($(package)_sha256_hash)) && \
$(call fetch_file,$(package),$($(package)_sodium_download_path),$($(package)_sodium_download_file),$($(package)_sodium_file_name),$($(package)_sodium_sha256_hash)) && \
$(call fetch_file,$(package),$($(package)_relic_download_path),$($(package)_relic_download_file),$($(package)_relic_file_name),$($(package)_relic_sha256_hash))
endef

define $(package)_extract_cmds
  mkdir -p $($(package)_extract_dir) && \
  echo "$($(package)_sha256_hash)  $($(package)_source)" > $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  echo "$($(package)_sodium_sha256_hash)  $($(package)_source_dir)/$($(package)_sodium_file_name)" >> $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  echo "$($(package)_relic_sha256_hash)  $($(package)_source_dir)/$($(package)_relic_file_name)" >> $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  $(build_SHA256SUM) -c $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  tar --strip-components=1 -xf $($(package)_source) -C . && \
  cp $($(package)_source_dir)/$($(package)_sodium_file_name) . && \
  cp $($(package)_source_dir)/$($(package)_relic_file_name) .
endef

define $(package)_set_vars
  $(package)_config_opts=-DCMAKE_INSTALL_PREFIX=$(host_prefix)
  $(package)_config_opts+= -DCMAKE_PREFIX_PATH=$(host_prefix)
  $(package)_config_opts+= -DSTLIB=ON -DSHLIB=OFF -DSTBIN=OFF
  $(package)_config_opts+= -DBUILD_BLS_PYTHON_BINDINGS=0 -DBUILD_BLS_TESTS=0 -DBUILD_BLS_BENCHMARKS=0
  $(package)_config_opts_linux=-DOPSYS=LINUX -DCMAKE_SYSTEM_NAME=Linux
  $(package)_config_opts_darwin=-DOPSYS=MACOSX -DCMAKE_SYSTEM_NAME=Darwin
  $(package)_config_opts_mingw32=-DOPSYS=WINDOWS -DCMAKE_SYSTEM_NAME=Windows -DCMAKE_SHARED_LIBRARY_LINK_C_FLAGS=""
  $(package)_config_opts_i686+= -DWSIZE=32
  $(package)_config_opts_x86_64+= -DWSIZE=64
  $(package)_config_opts_arm+= -DWSIZE=32
  $(package)_config_opts_armv7l+= -DWSIZE=32
  $(package)_config_opts_debug=-DDEBUG=ON -DCMAKE_BUILD_TYPE=Debug

  ifneq ($(darwin_native_toolchain),)
    $(package)_config_opts_darwin+= -DCMAKE_AR="$($(package)_ar)"
    $(package)_config_opts_darwin+= -DCMAKE_RANLIB="$($(package)_ranlib)"
  endif

  $(package)_cppflags+= -UBLSALLOC_SODIUM
endef

define $(package)_preprocess_cmds
  sed -i.old "s|GIT_REPOSITORY https://github.com/AmineKhaldi/libsodium-cmake.git|URL \"../../sodium-$($(package)_sodium_version).tar.gz\"|" CMakeLists.txt && \
  sed -i.old "s|GIT_TAG f73a3fe1afdc4e37ac5fe0ddd401bf521f6bba65|GIT_TAG \"\"|" CMakeLists.txt && \
  sed -i.old "s|GIT_REPOSITORY https://github.com/Chia-Network/relic.git|URL \"../../relic-$($(package)_relic_version).tar.gz\"|" CMakeLists.txt && \
  sed -i.old "s|RELIC_GIT_TAG \".*\"|RELIC_GIT_TAG \"\"|" CMakeLists.txt
endef

define $(package)_config_cmds
  export CC="$($(package)_cc)" && \
  export CXX="$($(package)_cxx)" && \
  export CFLAGS="$($(package)_cflags) $($(package)_cppflags)" && \
  export CXXFLAGS="$($(package)_cxxflags) $($(package)_cppflags)" && \
  export LDFLAGS="$($(package)_ldflags)" && \
  $(host_prefix)/bin/cmake ../ $($(package)_config_opts)
endef

define $(package)_build_cmds
  $(MAKE) $($(package)_build_opts)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef