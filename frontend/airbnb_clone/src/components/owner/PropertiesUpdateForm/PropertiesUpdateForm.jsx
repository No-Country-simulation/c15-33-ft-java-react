import { Button, Input, Typography } from '@material-tailwind/react';
import { useState } from 'react';
import { useLocation } from 'react-router-dom';
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faPenToSquare } from "@fortawesome/free-solid-svg-icons";

export const PropertiesUpdateForm = () => {

  let { state } = useLocation();

  const {description, country, value, image, id} = state;

  const [formData, setFormData] = useState({
    description,
    country,
    value,
    image,
    id,
  });

  const [isDescriptionEditing, setIsDescriptionEditing] = useState(false);
  const [isCountryEditing, setIsCountryEditing] = useState(false);
  const [isValueEditing, setIsValueEditing] = useState(false);
  const [isImageEditing, setIsImageEditing] = useState(false);

  const handleSubmit = (e) => {
      e.preventDefault();
      console.log('Formulario enviado:', formData);
  };
    
  const handleSave = (field) => {
      switch (field) {
        case 'description':
          setIsDescriptionEditing(false);
          break;
  
        case 'country':
          setIsCountryEditing(false);
          break;
  
        case 'value':
          setIsValueEditing(false);
          break;
  
        case 'image':
          setIsImageEditing(false);
          break;
      
        default:
          break;
      }
      console.log(`Guardando ${field}: ${formData[field]}`);
  };

  const handleEdit = (field) => {
      switch (field) {
        case 'description':
          setIsDescriptionEditing(true);
          break;
  
        case 'country':
          setIsCountryEditing(true);
          break;
  
        case 'value':
          setIsValueEditing(true);
          break;
  
        case 'image':
          setIsImageEditing(true);
          break;
      
        default:
          break;
      }
  };

  const handleChange = (field, value) => {
      setFormData({ ...formData, [field]: value });
  };

  return (
    <div className="container mx-auto mt-8">
        <form onSubmit={handleSubmit} className="max-w-md mx-auto bg-white rounded-lg shadow-none font-mono">
          <h2 className="text-2xl font-semibold mb-4">Información de la propiedad</h2>
          
          <div className="mb-4">
            <Typography variant="h5" className="mb-2">Descriptión</Typography>

            <Input name="description" maxLength="100" value={formData.description} onChange={(e) => handleChange('description', e.target.value)} readOnly={!isDescriptionEditing} icon={<FontAwesomeIcon onClick={() => handleEdit('description')} icon={faPenToSquare} />} />

            {isDescriptionEditing && (
              <Button className="mt-2" onClick={() => handleSave('description')}
              >
                Guardar
              </Button>
            )}
          </div>

          <div className="mb-4">
              <Typography variant="h5" className="mb-2">País</Typography>

              <Input name="country" maxLength="100" value={formData.country} onChange={(e) => handleChange('country', e.target.value)} readOnly={!isCountryEditing} icon={<FontAwesomeIcon onClick={() => handleEdit('country')} icon={faPenToSquare} />} />

              {isCountryEditing && (
                <Button className="mt-2" onClick={() => handleSave('country')}
                >
                  Guardar
                </Button>
              )}
          </div>

          <div className="mb-4">
              <Typography variant="h5" className="mb-2">Precio</Typography>

              <Input name="value" maxLength="100" value={formData.value} onChange={(e) => handleChange('value', e.target.value)} readOnly={!isValueEditing} icon={<FontAwesomeIcon onClick={() => handleEdit('value')} icon={faPenToSquare} />} />

              {isValueEditing && (
                <Button className="mt-2" onClick={() => handleSave('value')}
                >
                  Guardar
                </Button>
              )}
          </div>

          <div className="mb-4">
              <Typography variant="h5" className="mb-2">Imagen</Typography>

              <Input name="image" maxLength="100" value={formData.image} onChange={(e) => handleChange('image', e.target.value)} readOnly={!isImageEditing} icon={<FontAwesomeIcon onClick={() => handleEdit('image')} icon={faPenToSquare} />} />

              {isImageEditing && (
                <Button className="mt-2" onClick={() => handleSave('image')}
                >
                  Guardar
                </Button>
              )}
          </div>

          <div className="flex justify-center mt-4">
              <Button type="submit">Guardar cambios</Button>
          </div>
        </form>
    </div>
  )
}
