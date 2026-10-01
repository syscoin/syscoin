# Supplement the generated src/Makefile; use its real crypto compile rules.
PROFILE_OBJECTS = \
  crypto/slhdsa/vendor/libsyscoin_crypto_base_la-slh_dsa.lo \
  crypto/slhdsa/vendor/libsyscoin_crypto_base_la-slh_shake.lo \
  crypto/slhdsa/vendor/libsyscoin_crypto_base_la-sha3_api.lo \
  crypto/slhdsa/vendor/libsyscoin_crypto_base_la-sha3_f1600.lo \
  crypto/slhdsa/libsyscoin_crypto_base_la-secure.lo \
  crypto/slhdsa/libsyscoin_crypto_base_la-slhdsa.lo

pq-signing-profile-driver.lo: $(top_srcdir)/ci/profile/pq-signing.cpp
	$(LIBTOOL) --tag=CXX --mode=compile $(CXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(crypto_libsyscoin_crypto_base_la_CXXFLAGS) $(CXXFLAGS) -c $< -o $@

pq-signing-profile: pq-signing-profile-driver.lo $(PROFILE_OBJECTS)
	$(LIBTOOL) --tag=CXX --mode=link $(CXX) $(AM_CXXFLAGS) $(CXXFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -o $@ $^ $(PTHREAD_FLAGS)
