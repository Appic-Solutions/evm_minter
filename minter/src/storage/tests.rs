mod api_key {
    use crate::storage::{change_rpc_api_key, get_rpc_api_key};

    #[test]
    fn should_set_get_api_key() {
        change_rpc_api_key("test_key".to_string());

        assert_eq!(get_rpc_api_key(), "test_key".to_string());
    }
}
