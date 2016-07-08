struct test_data{
	int32_t val;
};

program TEST_RPC {
	version TEST_RPC_VERS {
		test_data test_rpc(test_data) = 1;
	} = 1;
} = 1001;
