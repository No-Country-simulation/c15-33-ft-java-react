
package com.clonair.back.property;

import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/property")
public class PropertyController {
    
    private final PropertyService propertyService;

    @GetMapping("{id}")
    public ResponseEntity<PropertyResponse> getOne(@PathVariable String id, @RequestHeader(name = HttpHeaders.AUTHORIZATION) String token) throws Exception{
        return ResponseEntity.ok(propertyService.getOne(id, token));
    }

    @GetMapping()
    public ResponseEntity<List<PropertyResponse>> getAll(@RequestHeader(name = HttpHeaders.AUTHORIZATION) String token) throws Exception{
        return ResponseEntity.ok(propertyService.getAll(token));
    }

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public void register(
            @RequestHeader(name = HttpHeaders.AUTHORIZATION) String token,
            @RequestParam("title") String title,
            @RequestParam("category") String category,
            @RequestParam("subCategory") String subCategory,
            @RequestParam("description") String description,
            @RequestParam("value") double value,
            @RequestParam("active") boolean active,
            @RequestParam("images") List<MultipartFile> images,
            @RequestParam("availability") List<String> availability,
            @RequestParam("country") String country,
            @RequestParam("city") String city,
            @RequestParam("bathroom") int bathroom,
            @RequestParam("bed") int bed,
            @RequestParam("bedroom") int bedroom,
            @RequestParam("services") List<String> services
    ) throws Exception {
        PropertyRequest propertyRequest = new PropertyRequest(title, category, subCategory, description, value, active, images, availability, country, city, bathroom, bed, bedroom, services);
        propertyService.save(token, propertyRequest);
    }

    @PutMapping("/{id}")
    public void update(
            @PathVariable String id,
            @RequestHeader(name = HttpHeaders.AUTHORIZATION) String token,
            @RequestParam("title") String title,
            @RequestParam("category") String category,
            @RequestParam("subCategory") String subCategory,
            @RequestParam("description") String description,
            @RequestParam("value") double value,
            @RequestParam("active") boolean active,
            @RequestParam("images") List<MultipartFile> images,
            @RequestParam("availability") List<String> availability,
            @RequestParam("country") String country,
            @RequestParam("city") String city,
            @RequestParam("bathroom") int bathroom,
            @RequestParam("bed") int bed,
            @RequestParam("bedroom") int bedroom,
            @RequestParam("services") List<String> services
    ) throws Exception {
        PropertyRequest propertyRequest = new PropertyRequest(title, category, subCategory, description, value, active, images, availability, country, city, bathroom, bed, bedroom, services);
        propertyService.update(id, token, propertyRequest);
    }

    @DeleteMapping()
    public void delete(@PathVariable String id, @RequestHeader(name = HttpHeaders.AUTHORIZATION) String token ) throws Exception{
        propertyService.delete(id, token);
    }
    
}
