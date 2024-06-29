
package com.clonair.back.image;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("v1/api/img")
public class ImageController {
    
    private final ImageService imageService;

    @GetMapping("/{id}/url")
    public ResponseEntity<String> getImageUrl(@PathVariable String id) throws Exception {
        String imageUrl = imageService.getUrl(id);
        return ResponseEntity.ok(imageUrl);
    }

    @GetMapping("/{id}")
    public ResponseEntity<byte[]> getImageData(@PathVariable String id) throws Exception {
        Image image = imageService.getOne(id);
        byte[] img = image.getContent();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.valueOf(image.getMime()));
        return new ResponseEntity<>(img, headers, HttpStatus.OK);
    }

    @PostMapping()
    public ResponseEntity<Image> uploadImage(@RequestParam("file") MultipartFile file) throws Exception {
        Image savedImage = imageService.saveOne(file);
        return ResponseEntity.ok(savedImage);
    }

    @PostMapping("/multi")
    public ResponseEntity<List<Image>> uploadMultipleImages(@RequestParam("files") MultipartFile[] files) throws Exception {
        List<Image> savedImages = imageService.saveMulti(files);
        return ResponseEntity.ok(savedImages);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Image> updateImage(@PathVariable String id, @RequestParam("file") MultipartFile file) throws Exception {
        Image updatedImage = imageService.updateOne(file, id);
        return ResponseEntity.ok(updatedImage);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteImage(@PathVariable String id) throws Exception {
        imageService.delete(id);
        return ResponseEntity.noContent().build();
    }

}
