
package com.clonair.back.user;

import java.util.List;
import java.util.Optional;

public interface UserService {

    User findById(String id);

    public Optional<User> findByUsername(String username);

    public UserResponse getOne(String id, String token) throws Exception;

    public List<UserResponse> getAll(String token) throws Exception;

    public void delete(String id, String token) throws Exception;
    
}
