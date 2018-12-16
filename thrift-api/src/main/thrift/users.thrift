namespace java thrift.users
#@namespace scala thrift.users

service UsersService {
    string find(1: i64 id);
}
