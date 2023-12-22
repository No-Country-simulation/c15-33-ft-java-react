import { Button, Checkbox, Dialog, DialogBody, DialogFooter, DialogHeader, Input, Option, Select,  Textarea, Typography } from "@material-tailwind/react";
import { useState } from "react";
import { useEffect } from "react";
import { CountriesSelect } from '../countries/CountryList'
import { submitProperty } from "../../services/apiRequests.jsx";
import { Link } from "react-router-dom";

const categories = [
    {
        name: "Departamento",
        value: "apartment"
    },
    {
        name: "Casa",
        value: "house"
    },
    {
        name: "Casa Huéspedes",
        value: "guest_house"
    },
    {
        name: "Hotel",
        value: "hotel"
    }
];

const subcategories = [
    {
        name: "Playa",
        value: "beach"
    },
    {
        name: "Lago",
        value: "lake"
    },
    {
        name: "Montaña",
        value: "mountain"
    },
    {
        name: "Campo",
        value: "countryside"
    },
    {
        name: "Pileta",
        value: "swimming_pool"
    },
    {
        name: "Urbana",
        value: "urban"
    },
    {
        name: "Tropical",
        value: "tropical"
    },
    {
        name: "Cabaña",
        value: "cabin"
    },
    {
        name: "Camping",
        value: "camping"
    }
];

const quantity = ["1", "2", "3", "4", "5", "6+"];

const services = [
    {text: "Wi-Fi", value: "wifi" },
    {text: "Cocina", value: "kitchen" },
    {text: "Lavarropas", value: "washing_machine" },
    {text: "Aire Acondicionado", value: "air_conditioner" },
    {text: "Calefacción", value: "heating" },
    {text: "Pileta", value: "swimming_pool" },
    {text: "Estacionamiento", value: "parking_lot" },
    {text: "Cuna", value: "cradle" },
    {text: "Parilla", value: "grill" },
    {text: "Desayuno", value: "breakfast" },
    {text: "Se puede fumar", value: "smoking_allowed" },
    {text: "Permite mascotas", value: "pets_allowed" },
    {text: "Cancelación anticipada", value: "early_cancellation"}
];


export const PropertyRegister = () => {
    const [openDialog, setOpenDialog] = useState(false);
    const handleOpenDialog = () => setOpenDialog(!openDialog);


    const [propertyData, setPropertyData] = useState({
        title: null,
        description: null,
        images: [],
        value: null,
        country: null,
        city: "ciudad",
        category: null,
        subCategory: null,
        bathroom: null,
        bed: null,
        bedroom: null,
        serviceTypes: [],
        active: 'true',
    })


    const [countryValue, setCountryValue] = useState('')

   
    const handleInputChange = (e) => {
        const { name, value } = e.target;
        setPropertyData((prevData) => ({
          ...prevData,
          [name]: value,
        }));
    };

    const handleSelectChange = (name, value) => {
        setPropertyData((prevData) => ({
            ...prevData,
            [name]: value,
        }));
    };

    const handleCheckboxChange = (value) => {
        setPropertyData((prevData) => {
          let updatedServices;
          
          if (prevData.serviceTypes.includes(value)) {
            updatedServices = prevData.serviceTypes.filter((service) => service !== value);
          } else {
            updatedServices = [...prevData.serviceTypes, value];
          }
      
          return {
            ...prevData,
            serviceTypes: updatedServices,
          };
        });
    };


    const handleFileChange = (event) => {
        const fileList = event.target.files;
        const imageArray = Array.from(fileList).map((file) => ({
          file,
          previewURL: URL.createObjectURL(file),
        }));
    
        setPropertyData((prevData) => ({
          ...prevData,
          images: [...prevData.images, ...imageArray],
        }));
    };

    useEffect(() => {
        handleSelectChange("country", countryValue)
    }, [countryValue])

    


    const sendPropertyInfo = () => {

        submitProperty(propertyData)
        handleOpenDialog()

    }


    return (
        <div className="flex flex-col items-center mb-8 px-14">
            <Typography variant="h3" className="text-center my-8">
                Información de la propiedad
            </Typography>
            <div className="flex md:w-5/12 w-full flex-col justify-center gap-6">
    
                <div className="flex flex-col gap-2">
                    <Typography variant="h5">
                        Titulo
                    </Typography>
                    <Typography color="gray" variant="small">
                        Escribí un título llamativo. Por este nombre será llamada tu propiedad.
                    </Typography>
                    <Input name="title" maxLength="100" onChange={handleInputChange} />
                </div>
    
                <div className="flex flex-col gap-2">
                    <Typography variant="h5">
                        Descripción
                    </Typography>
                    <Typography color="gray" variant="small">
                        Describí lo mejor posible tu propiedad para atraer más clientes.
                    </Typography>
                    <Textarea name="description" size="md" maxLength="500" onChange={handleInputChange}/>
                </div>
    
                <div className="flex flex-col gap-2">
                    <Typography variant="h5">
                        Fotos
                    </Typography>
                    <Typography color="gray" variant="small">
                        Subí las fotos de tu propiedad
                    </Typography>
                    <input
                        name="images"
                        type="file"
                        multiple
                        accept=".jpg, .jpeg, .png, .webp"
                        onChange={handleFileChange}
                    />
                </div>
    
                <div className="flex flex-col gap-2">
                    <Typography variant="h5">
                        Precio
                    </Typography>
                    <Typography color="gray" variant="small">
                        Por noche en USD.
                    </Typography>
                    <div className="md:w-4/12 w-full">
                        <Input name="value" type="number" onChange={handleInputChange}/>
                    </div>
                </div>
    
                <div className="flex flex-col gap-2 md:w-7/12 w-full">
                    <Typography variant="h5">
                        País
                    </Typography>
                    <Typography color="gray" variant="small">
                        Elegí el país donde está ubicada la propiedad
                    </Typography>
                    <CountriesSelect name="country" newValue={countryValue} setCountryValue={setCountryValue} newError={false}/>
                </div>
    
                <div className="flex flex-col gap-2 md:w-7/12 w-full">
                    <Typography variant="h5">
                        Categoría
                    </Typography>
                    <Typography color="gray" variant="small">
                        Seleccioná el tipo de alojamiento
                    </Typography>
                    <Select
                    name="category"
                    label="Categoría"
                    onChange={(value) => handleSelectChange("category", value)}
                    >
                        {categories.map((category, index) => (
                            <Option key={index} value={category.value}>{category.name}</Option>
                        ))}
                    </Select>
                    <Select
                    name="subCategory"
                    label="Subcategoría"
                    onChange={(value) => handleSelectChange("subCategory", value)}
                    >
                        {subcategories.map((subCategory, index) => (
                            <Option key={index} value={subCategory.value}>{subCategory.name}</Option>
                        ))}
                    </Select>
                </div>
    
                <div className="flex flex-col gap-2 md:w-7/12 w-full">
                    <Typography variant="h5">
                        Detalles
                    </Typography>
                    <Typography color="gray" variant="small">
                        Cantidad de baños (incluyendo toilette)
                    </Typography>
                    <Select
                    name="bathroom"
                    onChange={(value) => handleSelectChange("bathroom", value)}
                    >
                        {quantity.map((quantity, index) => (
                            <Option key={index} value={quantity.charAt(0)}>{quantity}</Option>
                        ))}
                    </Select>
                    <Typography color="gray" variant="small">
                        Cantidad de camas
                    </Typography>
                    <Select
                    name="bed"
                    onChange={(value) => handleSelectChange("bed", value)}
                    >
                        {quantity.map((quantity, index) => (
                            <Option key={index} value={quantity.charAt(0)}>{quantity}</Option>
                        ))}
                    </Select>
                    <Typography color="gray" variant="small">
                        Cantidad de dormitorios
                    </Typography>
                    <Select
                    name="bedroom"
                    onChange={(value) => handleSelectChange("bedroom", value)}
                    >
                        {quantity.map((quantity, index) => (
                            <Option key={index} value={quantity.charAt(0)}>{quantity}</Option>
                        ))}
                    </Select>
                </div>
    
                <Typography variant="h4">
                    Servicios disponibles
                </Typography>
                <div className="flex flex-wrap">
                    {services.map((service, index) => (
                        <Checkbox
                        name={service.value}
                        key={index}
                        label={service.text} 
                        onChange={() => handleCheckboxChange(service.value)}
                        />
                    ))}
                </div>
                   
    
                <div className="flex justify-center">
                    <Button className="mt-4" onClick={sendPropertyInfo}>Enviar Formulario</Button>
                    <Dialog open={openDialog} handler={handleOpenDialog}>
                            <DialogHeader>¡Propiedad Registrada!</DialogHeader>
                            <DialogBody>                              
                              <Typography variant="h6">Los datos fueron cargados con éxito.</Typography>                            
                            </DialogBody>
                            <DialogFooter>
                              <Button
                                variant="text"
                                color="red"
                                onClick={handleOpenDialog}
                                className="mr-1"
                              >
                                <span>Cerrar</span>
                              </Button>
                              <Link to="/">
                              <Button variant="gradient" color="green">
                                <span>Volver a Inicio</span>
                              </Button></Link>
                            </DialogFooter>
                    </Dialog>
                </div>
            </div>
        </div>
    );
    
};
