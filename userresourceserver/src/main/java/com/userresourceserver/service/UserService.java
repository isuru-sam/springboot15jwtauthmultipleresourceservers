package com.userresourceserver.service;



import java.util.List;

import com.userresourceserver.model.User;


public interface UserService {

    User save(User user);
    List<User> findAll();
    void delete(long id);
}
