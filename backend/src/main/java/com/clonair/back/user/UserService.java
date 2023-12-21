
package com.clonair.back.user;

import com.clonair.back.property.PropertyRequest;

import java.util.List;
import java.util.Optional;

public interface UserService {

    public UserResponse getByUsername(String username) throws Exception;

    public User findById(String id);

    public Optional<User> findByUsername(String username);

    public UserResponse getOne(String id, String token) throws Exception;

    public List<UserResponse> getAll(String token) throws Exception;

    public void update(String id, String token, UserRequest request) throws Exception;

    public void delete(String id, String token) throws Exception;
    
}
