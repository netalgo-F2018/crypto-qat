
include $(PWD)/common.mk

EXTRA_CFLAGS+=-std=gnu99
#EXTRA_CFLAGS+=-DRT_DEBUG

OUTPUT_NAME = file_encryptor
USER_SOURCE_FILES += common/cpa_sample_utils.c file_encryptor.c

build_test: rt_utils_test

rt_utils_test: rt_utils_test.c
	rm -f $@
	$(CC) $(USER_INCLUDES) $(EXTRA_CFLAGS) -DUSER_SPACE $^ $(ADDITIONAL_OBJECTS) -o $@	
cscope:
	cscope -bqR

