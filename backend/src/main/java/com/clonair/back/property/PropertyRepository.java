
package com.clonair.back.property;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.clonair.back.user.User;

@Repository
public interface PropertyRepository extends JpaRepository<Property,String> {
    
    public List<Property> findByCategory(Category category);
    public List<Property> findByUser(User user);
    
}
