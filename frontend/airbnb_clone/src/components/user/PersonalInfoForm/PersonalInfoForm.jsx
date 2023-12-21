import { useState } from "react";
import { Button, Input, Typography } from "@material-tailwind/react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faPenToSquare } from "@fortawesome/free-solid-svg-icons";

export const PersonalInfoForm = () => {

  const [formData, setFormData] = useState({
    name: 'John Doe',
    email: 'john@example.com',
    phone: '123-456-7890',
    dni: '12345678',
    direccion: '123 Main St',
  });

  const [isNameEditing, setIsNameEditing] = useState(false);
  const [isEmailEditing, setIsEmailEditing] = useState(false);
  const [isPhoneEditing, setIsPhoneEditing] = useState(false);
  const [isDniEditing, setIsDniEditing] = useState(false);
  const [isDireccionEditing, setIsDireccionEditing] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    console.log('Formulario enviado:', formData);
  };

  const handleSave = (field) => {
    switch (field) {
      case 'name':
        setIsNameEditing(false);
        break;

      case 'email':
        setIsEmailEditing(false);
        break;

      case 'phone':
        setIsPhoneEditing(false);
        break;

      case 'dni':
        setIsDniEditing(false);
        break;

      case 'direccion':
        setIsDireccionEditing(false);
        break;
    
      default:
        break;
    }
    console.log(`Guardando ${field}: ${formData[field]}`);
  };

  // Manejador para habilitar la edición de un campo específico
  const handleEdit = (field) => {

    switch (field) {
      case 'name':
        setIsNameEditing(true);
        break;

      case 'email':
        setIsEmailEditing(true);
        break;

      case 'phone':
        setIsPhoneEditing(true);
        break;

      case 'dni':
        setIsDniEditing(true);
        break;

      case 'direccion':
        setIsDireccionEditing(true);
        break;
    
      default:
        break;
    }
  };

  // Manejador para cambiar el valor de un campo en el estado
  const handleChange = (field, value) => {
    setFormData({ ...formData, [field]: value });
  };

  return (
    <div className="container mx-auto mt-8">
        <form onSubmit={handleSubmit} className="max-w-md mx-auto bg-white rounded-lg shadow-none font-mono">
          <h2 className="text-2xl font-semibold mb-4">Información personal</h2>
          
          <div className="mb-4">
            <Typography variant="h5" className="mb-2">Nombre</Typography>

            <Input name="name" maxLength="200" value={formData.name} onChange={(e) => handleChange('name', e.target.value)} readOnly={!isNameEditing} icon={<FontAwesomeIcon onClick={() => handleEdit('name')} icon={faPenToSquare} />} />

            {isNameEditing && (
              <Button className="mt-2" onClick={() => handleSave('name')}
              >
                Guardar
              </Button>
            )}
          </div>

          <div className="mb-4">
              <Typography variant="h5" className="mb-2">Correo electrónico</Typography>

              <Input name="email" maxLength="200" value={formData.email} onChange={(e) => handleChange('email', e.target.value)} readOnly={!isEmailEditing} icon={<FontAwesomeIcon onClick={() => handleEdit('email')} icon={faPenToSquare} />} />

              {isEmailEditing && (
                <Button className="mt-2" onClick={() => handleSave('email')}
                >
                  Guardar
                </Button>
              )}
          </div>

          <div className="mb-4">
              <Typography variant="h5" className="mb-2">Número de teléfono</Typography>

              <Input name="phone" maxLength="200" value={formData.phone} onChange={(e) => handleChange('phone', e.target.value)} readOnly={!isPhoneEditing} icon={<FontAwesomeIcon onClick={() => handleEdit('phone')} icon={faPenToSquare} />} />

              {isPhoneEditing && (
                <Button className="mt-2" onClick={() => handleSave('phone')}
                >
                  Guardar
                </Button>
              )}
          </div>

          <div className="mb-4">
              <Typography variant="h5" className="mb-2">Cédula de identidad</Typography>

              <Input name="dni" maxLength="200" value={formData.dni} onChange={(e) => handleChange('dni', e.target.value)} readOnly={!isDniEditing} icon={<FontAwesomeIcon onClick={() => handleEdit('dni')} icon={faPenToSquare} />} />

              {isDniEditing && (
                <Button className="mt-2" onClick={() => handleSave('dni')}
                >
                  Guardar
                </Button>
              )}
          </div>

          <div className="mb-4">
              <Typography variant="h5" className="mb-2">Dirección</Typography>

              <Input name="direccion" maxLength="200" value={formData.direccion} onChange={(e) => handleChange('direccion', e.target.value)} readOnly={!isDireccionEditing} icon={<FontAwesomeIcon onClick={() => handleEdit('direccion')} icon={faPenToSquare} />} />

              {isDireccionEditing && (
                <Button className="mt-2" onClick={() => handleSave('direccion')}
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
