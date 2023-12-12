import { Button, Checkbox, Input, Option, Select, Switch, Textarea, Typography } from "@material-tailwind/react"
import { countries } from 'countries-list'
import 'react-date-range/dist/styles.css';
import 'react-date-range/dist/theme/default.css';
import { DateRange } from 'react-date-range';
import { useRef, useState } from "react";

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
    
]

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
    
]

const quantity = [
    "1","2","3","4","5","6+"
]

const services = [
    "Wi-Fi", "Cocina", "Lavarropas", "Aire Acondicionado", "Calefacción", "Pileta", "Estacionamiento", "Cuna", "Parilla", "Desayuno", "Se puede fumar", "Permite mascotas", "Cancelación anticipada"
]


const countryList = []
for (const key in countries) {
    if (countries.hasOwnProperty(key)) {
      countryList.push(countries[key].name);
    }
  }

countryList.sort()


export const PropertyRegister = () => {

    const switchRef = useRef()

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
        setOpenDate(current => !current)
      }


    return(
        <div className="flex m-4 flex-col items-center h-full">
                    <Typography variant="h3">
                        Información de la propiedad
                    </Typography>
            <div className="w-full flex justify-around gap-6 p-5">

                <div className="w-5/12 flex flex-col gap-4 items-center">
                    <div className="flex flex-col gap-4 justify-between w-full h-full">
                        <Input label="Título"/>
                        <Textarea label="Descripción" size="md"/>
                        <Input label="Fotos" type="file" multiple accept=".jpg, .jpeg, .png" name="pictures"/>
                        <div className="flex gap-2 w-full">
                            <Input label="Precio" type="number" className="w-full"/>
                            <Select label="País" className="w-full">
                                {countryList.map((country, index) => (
                                    <Option key={index}>{country}</Option>
                                ))}
                            </Select>
                        </div>
                        <div className="flex gap-2 w-full">
                            <Select label="Categoría">
                                {categories.map((category, index)=>(
                                    <Option key={index} value={category.value}>{category.name}</Option>
                                    ))}
                            </Select>
                            <Select label="Subcategoría">
                                {subcategories.map((subcategory, index)=>(
                                    <Option key={index} value={subcategory.value}>{subcategory.name}</Option>
                                    ))}
                            </Select>
                            
                        </div>
                    </div>
                </div>
                
                <div className="w-5/12 flex flex-col gap-4 items-center">
                    <div className="flex flex-col gap-2 w-full h-full items-center">
                        <Select label="Baños">
                            {quantity.map((quantity, index)=>(
                                <Option key={index} value={quantity.charAt(0)}>{quantity}</Option>
                                ))}
                        </Select>
                        <Select label="Camas">
                            {quantity.map((quantity, index)=>(
                                <Option key={index} value={quantity.charAt(0)}>{quantity}</Option>
                                ))}
                        </Select>
                        <Select label="Dormitorios">
                            {quantity.map((quantity, index)=>(
                                <Option key={index} value={quantity.charAt(0)}>{quantity}</Option>
                                ))}
                        </Select>
                        <Typography variant="h4">
                            Servicios disponibles
                        </Typography>
                        <div className="flex w-full flex-wrap justify-center">
                            {services.map((service) => (
                                <Checkbox label={service}/>
                            ))}
                        </div>
                    </div>
                </div>

                <div className="w-4/12 flex flex-col items-center max-h-80">
                    <Switch defaultChecked label="Disponibilidad permanente" inputRef={switchRef} onChange={handleSwitch}/>
                    {openDate && (<DateRange
                        ranges={dateRange}
                        onChange={handleSelect}
                    />)}

                </div>

                
                
                
            </div>
            <Button className="mt-4">Enviar Formulario</Button>
        </div>
    )
}