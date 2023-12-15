
package com.clonair.back.image;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import com.clonair.back.property.Property;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

@Service
@Data
@RequiredArgsConstructor
public class ImageServiceImp implements ImageService{

    private final ImageRepository imageRepository;
    
    /**
     * Recupera un obj imagen por el nombre
     *@param -id de la imagen
     *@return el obj imagen o null si no existe
     */
    @Override
    @Transactional(readOnly = true)
    public Image getOne(String id) throws Exception{
        if(id != null){
            Optional<Image> img = imageRepository.findById(id);
            if(img.isPresent()){
               return img.get();
            }
        }
        return null;
    }
    
    /**
     * Persiste un obj imagen
     *@param input del MultipartFile de la imagen
     *@return el obj imagen o null si no paso el MultipartFile como parametro
     */
    @Override
    @Transactional
    public Image saveOne(MultipartFile input) throws Exception {
        if (input != null) {
            Image img = new Image();
            img.setMime(input.getContentType());
            img.setName(input.getOriginalFilename());
            img.setContent(input.getBytes());

            // Guardar la imagen en la base de datos
            Image savedImage = imageRepository.save(img);

            // Ahora que se ha guardado la imagen y se ha generado su ID, generamos la URL
            savedImage.setUrl(generateImageUrl(savedImage.getId()));

            // Actualizar la imagen con la URL en la base de datos
            return imageRepository.save(savedImage);
        }
        return null;
    }

    /**
     * Persiste una lista de obj imagen
     *@param -input del arreglo de MultipartFile de las imagenes,
     *@return la List de obj imagen o null si no paso el MultipartFile como parametro
     */
    @Override
    @Transactional
    public List<Image> saveMulti(MultipartFile[] input) throws Exception{
        if (input != null) {
            List<Image> images = new ArrayList<>();
            for (MultipartFile imageElem : input) {
                if(!imageElem.getContentType().contains("octet-stream")){
                    Image img = new Image();
                    img.setMime(imageElem.getContentType());
                    img.setName(imageElem.getOriginalFilename());
                    img.setContent(imageElem.getBytes());

                    Image savedImage = imageRepository.save(img);

                    // Configurar la URL para la imagen guardada
                    savedImage.setUrl(generateImageUrl(savedImage.getId()));

                    // Agregar la imagen con URL configurada a la lista
                    images.add(savedImage);
                }
            }
            return images;
        }
        return null;
    }

    /**
     * Actualiza un obj imagen
     *@param -input del MultipartFile de la imagen
     *@param -id id de la imagen a actualizar
     *@return el obj imagen o null si no paso el MultipartFile como parametro
     */
    @Override
    @Transactional
    public Image updateOne(MultipartFile input, String id) throws Exception {
        if (input != null) {
            try {
                Image img = new Image();
                if (id != null) {
                    Optional<Image> respuesta = imageRepository.findById(id);
                    if (respuesta.isPresent()) {
                        img = respuesta.get();
                    }
                }
                img.setMime(input.getContentType());
                img.setName(input.getOriginalFilename());
                img.setContent(input.getBytes());
                return imageRepository.save(img);
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        }
        return null;
    }

    /**
     * Persiste una lista de obj imagen
     *@param -input del arreglo de MultipartFile de las imagenes,
     *@return la List de obj imagen o null si no paso el MultipartFile como parametro
     */
    @Override
    @Transactional
    public List<Image> filter(List<Image> imageRepo, String[] imageIds) throws Exception{
        for (String imgId : imageIds) {
            Optional<Image> imgRp = imageRepository.findById(imgId);
            if (imgRp.isPresent()) {
                Image img = imgRp.get();
                if(imageRepo.contains(img)){
                    imageRepo.remove(img);
                }
                delete(img.getId());
            }
        }
        return imageRepo;
    }
    
    /**
     * Elimina un obj imagen
     *@param id de la imagen 
     */
    @Override
    @Transactional
    public void delete(String id) throws Exception{
        Optional<Image> img = imageRepository.findById(id);
        if (img.isPresent()) {
            imageRepository.deleteById(id);
        }        
    }

    @Override
    @Transactional(readOnly = true)
    public String getUrl(String id) {
        Image image = imageRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Image not found with ID: " + id));

        String base64EncodedImage = Base64.getEncoder().encodeToString(image.getContent());
        return "data:image/jpeg;base64," + base64EncodedImage;
    }

    // Implementación básica de generateImageUrl (ajústala según tus necesidades)
    @Override
    public String generateImageUrl(String imageId) {
        // Por ejemplo, una URL base de imágenes y concatenación con la ID
        return "blob:http://127.0.0.1:5500/" + imageId;
    }

    @Override
    @Transactional
    public List<Image> updatePropertyImages(Property existingProperty, List<MultipartFile> newImages) throws Exception {
        List<Image> existingImages = existingProperty.getImages();
        List<Image> updatedImages = new ArrayList<>();

        // Eliminar imágenes no presentes en la lista de imágenes nuevas
        List<String> newImageNames = newImages.stream()
                                              .map(MultipartFile::getOriginalFilename)
                                              .toList();

        for (Image image : existingImages) {
            if (!newImageNames.contains(image.getName())) {
                delete(image.getId()); // Eliminar imágenes no presentes en la lista nueva
            }
        }

        // Guardar las nuevas imágenes y actualizar las existentes
        for (MultipartFile newImageFile : newImages) {
            // Si la imagen ya existe, actualízala; de lo contrario, guárdala como nueva
            Image existingImage = existingImages.stream()
                    .filter(img -> img.getName().equals(newImageFile.getOriginalFilename()))
                    .findFirst()
                    .orElse(null);

            if (existingImage != null) {
                Image updatedImage = updateOne(newImageFile, existingImage.getId());
                if (updatedImage != null) {
                    updatedImages.add(updatedImage);
                }
            } else {
                Image savedImage = saveOne(newImageFile);
                if (savedImage != null) {
                    updatedImages.add(savedImage);
                }
            }
        }

        return updatedImages;
    }

}
