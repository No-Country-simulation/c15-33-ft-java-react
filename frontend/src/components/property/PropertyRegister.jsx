import { Button, Checkbox, Input, Option, Select, Switch, Textarea, Typography } from "@material-tailwind/react";
import { countries } from 'countries-list';
import 'react-date-range/dist/styles.css';
import 'react-date-range/dist/theme/default.css';
import { DateRange } from 'react-date-range';
import { useRef, useState } from "react";
import { useEffect } from "react";

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
    "Wi-Fi", "Cocina", "Lavarropas", "Aire Acondicionado", "Calefacción", "Pileta", "Estacionamiento", "Cuna", "Parilla", "Desayuno", "Se puede fumar", "Permite mascotas", "Cancelación anticipada"
];

const countryList = [];
for (const key in countries) {
    if (countries.hasOwnProperty(key)) {
        countryList.push(countries[key].name);
    }
}

countryList.sort();

export const PropertyRegister = () => {
    const switchRef = useRef();
    const [openDate, setOpenDate] = useState(false);
    const [dateRange, setDateRange] = useState([
        {
            startDate: new Date(),
            endDate: new Date(),
            key: 'selection',
        },
    ]);

    const handleSelect = (ranges) => {
        setDateRange([ranges.selection]);
    };

    const handleSwitch = () => {
        setOpenDate(current => !current);
    };

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
                    <Input name="title" maxLength="100" />
                </div>
    
                <div className="flex flex-col gap-2">
                    <Typography variant="h5">
                        Descripción
                    </Typography>
                    <Typography color="gray" variant="small">
                        Describí lo mejor posible tu propiedad para atraer más clientes.
                    </Typography>
                    <Textarea name="description" size="md" maxLength="500" />
                </div>
    
                <div className="flex flex-col gap-2">
                    <Typography variant="h5">
                        Fotos
                    </Typography>
                    <Typography color="gray" variant="small">
                        Subí las fotos de tu propiedad
                    </Typography>
                    <input
                        name="pictures"
                        type="file"
                        multiple
                        accept=".jpg, .jpeg, .png"
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
                        <Input type="number" />
                    </div>
                </div>
    
                <div className="flex flex-col gap-2 md:w-7/12 w-full">
                    <Typography variant="h5">
                        País
                    </Typography>
                    <Typography color="gray" variant="small">
                        Elegí el país donde está ubicada la propiedad
                    </Typography>
                    <Select label="País" className="w-full">
                        {countryList.map((country, index) => (
                            <Option key={index}>{country}</Option>
                        ))}
                    </Select>
                </div>
    
                <div className="flex flex-col gap-2 md:w-7/12 w-full">
                    <Typography variant="h5">
                        Categoría
                    </Typography>
                    <Typography color="gray" variant="small">
                        Seleccioná el tipo de alojamiento
                    </Typography>
                    <Select label="Categoría">
                        {categories.map((category, index) => (
                            <Option key={index} value={category.value}>{category.name}</Option>
                        ))}
                    </Select>
                    <Select label="Subcategoría">
                        {subcategories.map((subcategory, index) => (
                            <Option key={index} value={subcategory.value}>{subcategory.name}</Option>
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
                    <Select>
                        {quantity.map((quantity, index) => (
                            <Option key={index} value={quantity.charAt(0)}>{quantity}</Option>
                        ))}
                    </Select>
                    <Typography color="gray" variant="small">
                        Cantidad de camas
                    </Typography>
                    <Select>
                        {quantity.map((quantity, index) => (
                            <Option key={index} value={quantity.charAt(0)}>{quantity}</Option>
                        ))}
                    </Select>
                    <Typography color="gray" variant="small">
                        Cantidad de dormitorios
                    </Typography>
                    <Select>
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
                        <Checkbox key={index} label={service} />
                    ))}
                </div>
    
                <div className="flex flex-col gap-4 md:w-full w-full">
                    <Switch defaultChecked label="Disponibilidad permanente" inputRef={switchRef} onChange={handleSwitch} />
                    {openDate && (<DateRange
                        ranges={dateRange}
                        onChange={handleSelect}
                    />)}
                </div>
    
                <div className="flex justify-center">
                    <Button className="mt-4">Enviar Formulario</Button>
                </div>
            </div>
        </div>
    );
    
};
