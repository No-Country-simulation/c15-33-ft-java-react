
package com.clonair.back.image;

import java.util.List;

import com.clonair.back.property.Property;
import org.springframework.web.multipart.MultipartFile;

public interface ImageService {
       
    public Image getOne(String id) throws Exception;
    
    public Image saveOne(MultipartFile input) throws Exception;
    
    public Image updateOne(MultipartFile input, String id) throws Exception;
    
    public List<Image> saveMulti(MultipartFile[] input) throws Exception;
    
    public List<Image> filter(List<Image> imageRepo, String[] imageIds) throws Exception;
    
    public void delete(String id) throws Exception;

    public String getUrl(String id);

    public String generateImageUrl(String id);

    public List<Image> updatePropertyImages(Property existingProperty, List<MultipartFile> newImages) throws Exception;
    
}
