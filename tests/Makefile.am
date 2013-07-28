


# Python testing
if ENABLE_VTY_TESTS
python-tests: $(BUILT_SOURCES)
	osmotestvty.py -p $(abs_top_srcdir) -w $(abs_top_builddir) -v
	osmotestconfig.py -p $(abs_top_srcdir) -w $(abs_top_builddir) -v

else
python-tests: $(BUILT_SOURCES)
	@echo "Not running python-based tests (determined at configure-time)"
endif

check-local: $(BUILT_SOURCES)
	$(MAKE) $(AM_MAKEFLAGS) python-tests
