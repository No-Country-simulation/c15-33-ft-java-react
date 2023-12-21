
package com.clonair.back.property;

import java.util.List;

public interface PropertyService {
    
    public PropertyResponse getOne(String id) throws Exception;

    public List<PropertyResponse> getAll() throws Exception;

    public List<PropertyResponse> getByUser(String id) throws Exception;

    public List<PropertyResponse> getByCategory(String category) throws Exception;

    public void save(String token, PropertyRequest request) throws Exception;
    
    public void update(String id,String token, PropertyRequest request) throws Exception;

    public List<PropertyResponse> filtered(String category) throws Exception;
    
    public void delete(String id, String token) throws Exception;
    
}
