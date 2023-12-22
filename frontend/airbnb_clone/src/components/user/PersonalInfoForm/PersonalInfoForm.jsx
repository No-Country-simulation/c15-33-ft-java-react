import { useState } from "react";
import { Button, Input, Typography } from "@material-tailwind/react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faPenToSquare } from "@fortawesome/free-solid-svg-icons";
import { useLocation } from "react-router-dom";
import { updateUser } from "../../../services/apiRequests";

export const PersonalInfoForm = () => {
  let { state } = useLocation();
  const { id, username , firstname, lastname, country, propertyIds, contact, description } = state;

  console.log(firstname,
    lastname,
    contact,
    country,
    description);

  const [ formData, setFormData ] = useState({
    firstname: firstname || "",
    lastname: lastname || "",
    contact: contact || "",
    country: country || "",
    description: description || "",
  });

  const [isFirstnameEditing, setIsFirstnameEditing] = useState(false);
  const [isLastnameEditing, setIsLastnameEditing] = useState(false);
  // const [isUsernameEditing, setIsUsernameEditing] = useState(false);
  const [isContactEditing, setIsContactEditing] = useState(false);
  const [isCountryEditing, setIsCountryEditing] = useState(false);
  const [isDescriptionEditing, setIsDescriptionEditing] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const data = await updateUser(formData, id);
      setFormData(data);
      console.log('Formulario enviado:', formData);
    } catch (error) {
      console.error('Error al enviar actualizar la info del usuario:', error);
    }
  };

  // const handleSubmit = (e) => {
  //   e.preventDefault();
  //   console.log('Formulario enviado:', formData);
  // };

  // Manejador para cambiar el valor de un campo en el estado
  const handleChange = (field, value) => {
    setFormData({ ...formData, [field]: value });
  };

  const handleSave = (field) => {
    switch (field) {
      case 'firstname':
        setIsFirstnameEditing(false);
        break;

      case 'lastname':
        setIsLastnameEditing(false);
        break;

      // case 'username':
      //   setIsUsernameEditing(false);
      //   break;

      case 'contact':
        setIsContactEditing(false);
        break;

      case 'country':
        setIsCountryEditing(false);
        break;

      case 'description':
        setIsDescriptionEditing(false);
        break;
    
      default:
        break;
    }
    console.log(`Guardando ${field}: ${formData[field]}`);
  };

  // Manejador para habilitar la edición de un campo específico
  const handleEdit = (field) => {
    switch (field) {
      case 'firstname':
        setIsFirstnameEditing(true);
        break;

      case 'lastname':
        setIsLastnameEditing(true);
        break;

      // case 'username':
      //   setIsUsernameEditing(true);
      //   break;

      case 'contact':
        setIsContactEditing(true);
        break;

      case 'country':
        setIsCountryEditing(true);
        break;

      case 'description':
        setIsDescriptionEditing(true);
        break;
    
      default:
        break;
    }
  };

  return (
    <div className="container mx-auto mt-8">
        <form onSubmit={handleSubmit} className="max-w-md mx-auto bg-white rounded-lg shadow-none font-mono">
          <h2 className="text-2xl font-semibold mb-4">Información personal</h2>
          
          <div className="mb-4">
            <Typography variant="h5" className="mb-2">Primer nombre</Typography>

            <Input
              name="firstname"
              maxLength="100"
              value={formData.firstname}
              onChange={(e) => handleChange('firstname', e.target.value)}
              readOnly={!isFirstnameEditing}
              icon={<FontAwesomeIcon onClick={() => handleEdit('firstname')} icon={faPenToSquare} />}
            />

            {isFirstnameEditing && (
              <Button className="mt-2" onClick={() => handleSave('firstname')}
              >
                Guardar
              </Button>
            )}
          </div>

          <div className="mb-4">
            <Typography variant="h5" className="mb-2">Segundo nombre</Typography>

            <Input
              name="lastname"
              maxLength="100"
              value={formData.lastname}
              onChange={(e) => handleChange('lastname', e.target.value)}
              readOnly={!isLastnameEditing}
              icon={<FontAwesomeIcon onClick={() => handleEdit('lastname')} icon={faPenToSquare} />}
            />

            {isLastnameEditing && (
              <Button className="mt-2" onClick={() => handleSave('lastname')}
              >
                Guardar
              </Button>
            )}
          </div>

          {/* <div className="mb-4">
              <Typography variant="h5" className="mb-2">Correo electrónico</Typography>

              <Input name="username" maxLength="100" value={formData.username} onChange={(e) => handleChange('username', e.target.value)} readOnly={!isUsernameEditing} icon={<FontAwesomeIcon onClick={() => handleEdit('username')} icon={faPenToSquare} />} />

              {isUsernameEditing && (
                <Button className="mt-2" onClick={() => handleSave('username')}
                >
                  Guardar
                </Button>
              )}
          </div> */}

          <div className="mb-4">
              <Typography variant="h5" className="mb-2">Número de teléfono</Typography>

              <Input name="contact" maxLength="100" value={formData.contact} onChange={(e) => handleChange('contact', e.target.value)} readOnly={!isContactEditing} icon={<FontAwesomeIcon onClick={() => handleEdit('contact')} icon={faPenToSquare} />} />

              {isContactEditing && (
                <Button className="mt-2" onClick={() => handleSave('contact')}
                >
                  Guardar
                </Button>
              )}
          </div>

          <div className="mb-4">
            <Typography variant="h5" className="mb-2">País</Typography>

            <Input
              name="country"
              maxLength="100"
              value={formData.country}
              onChange={(e) => handleChange('country', e.target.value)}
              readOnly={!isCountryEditing}
              icon={<FontAwesomeIcon onClick={() => handleEdit('country')} icon={faPenToSquare} />}
            />

            {isCountryEditing && (
              <Button className="mt-2" onClick={() => handleSave('country')}
              >
                Guardar
              </Button>
            )}
          </div>

          <div className="mb-4">
              <Typography variant="h5" className="mb-2">Descripción</Typography>

              <Input
                name="description"
                maxLength="200"
                value={formData.description} onChange={(e) => handleChange('description', e.target.value)}
                readOnly={!isDescriptionEditing} icon={<FontAwesomeIcon onClick={() => handleEdit('description')}
                icon={faPenToSquare} />}
              />

              {isDescriptionEditing && (
                <Button className="mt-2" onClick={() => handleSave('description')}
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
