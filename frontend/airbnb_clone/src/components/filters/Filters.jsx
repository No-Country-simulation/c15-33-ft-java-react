import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faBuilding, faFilter, faHotel, faHouse, faWarehouse } from "@fortawesome/free-solid-svg-icons";
import {
    Button,
    Dialog,
    DialogHeader,
    DialogBody,
    DialogFooter,    
    Input,
    Radio,
    Checkbox,
  } from "@material-tailwind/react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";

export const Filters = () => {    
    const [open, setOpen] = useState(false);
    const navigate = useNavigate();    
    
    const handleOpen = () => {
        setOpen(!open)        
    };

    const clearFilters = () => {
        setMinValue(0), 
        setMaxValue(1000),
        setSelectedTypes([]),
        setSelectedRooms('cualquiera'),
        setSelectedBeds('cualquiera'),
        setSelectedBaths('cualquiera'),
        handleClearCheckboxes()
    }    

    //Price inputs
    const [minValue, setMinValue] = useState(0);
    const [maxValue, setMaxValue] = useState(1000);
  
    const handleMinChange = (event) => {
      const value = parseInt(event.target.value);
      if (!isNaN(value) && value <= maxValue) {
        setMinValue(value);
      }
    };
  
    const handleMaxChange = (event) => {
      const value = parseInt(event.target.value);
      if (!isNaN(value) && value >= minValue) {
        setMaxValue(value);
      }
    }; 
    
    //Property Types Buttons
    const [selectedTypes, setSelectedTypes] = useState([]);

    const handleTypeSelection = (type) => {
        const updatedSelection = [...selectedTypes]; 
        
        if (updatedSelection.includes(type)) {
        updatedSelection.splice(updatedSelection.indexOf(type), 1); 
        } else {
        updatedSelection.push(type); 
        }
        setSelectedTypes(updatedSelection); 
    };

    const isButtonSelected = (type) => {
        return selectedTypes.includes(type);
    };

    const getButtonClassName = (type) => {
        return `flex flex-col gap-4 items-center justify-center w-32 h-24 
        ${isButtonSelected(type) ? 'bg-red-300' : ''}`;
    };

    //Radio Buttons
    const [selectedRooms, setSelectedRooms] = useState('cualquiera');
    const [selectedBeds, setSelectedBeds] = useState('cualquiera');
    const [selectedBaths, setSelectedBaths] = useState('cualquiera'); 

    const handleRoomSelection = (value) => {
        setSelectedRooms(value);
    };

    const handleBedSelection = (value) => {
        setSelectedBeds(value);
    };

    const handleBathSelection = (value) => {
        setSelectedBaths(value);
    }; 

    //Checkbox
    const [checkboxes, setCheckboxes] = useState({
        WIFI: false,
        KITCHEN: false,
        WASHING_MACHINE: false,
        AIR_CONDITIONER: false,
        HEATING: false,
        SWIMMING_POOL: false,
        PARKING_LOT: false,
        CRADLE: false,
        GRILL: false,
        BREAKFAST: false,
        SMOKING_ALLOWED: false,
        PETS_ALLOWED: false,
        EARLY_CANCELLATION: false
    });
    
    const handleCheckboxChange = (e) => {
        const checkboxId = e.target.id;
        setCheckboxes({
          ...checkboxes,
          [checkboxId]: !checkboxes[checkboxId],
        });
    };

    const handleClearCheckboxes = () => {
        const clearedCheckboxes = Object.fromEntries(
          Object.keys(checkboxes).map((key) => [key, false])
        );
        setCheckboxes(clearedCheckboxes);
    };
    
      
    //Filters Submit Button
    const handleFilters = () => {            
        
        const searchParams = new URLSearchParams();  
          
        searchParams.set('minValue', minValue);
        searchParams.set('maxValue', maxValue);
        searchParams.set('propType', selectedTypes);
        searchParams.set('selectedRooms', selectedRooms);
        searchParams.set('selectedBeds', selectedBeds);
        searchParams.set('selectedBaths', selectedBaths);
        searchParams.set('services', JSON.stringify(checkboxes)); 
          
        navigate(`/filtered-filters?${searchParams.toString()}`);
        handleOpen();
    };
  

    return (
        <>
            <Button onClick={handleOpen} variant="outlined"  className="w-32 p-8 md:pl-6 h-14 text-sm flex flex-col md:flex-row items-center justify-center gap-2">
                <FontAwesomeIcon icon={faFilter}/>
                <h2>Filtrar</h2>
            </Button>
            <Dialog open={open} handler={handleOpen} size="lg">
                <DialogHeader className="pl-10">Filtros</DialogHeader>
                <DialogBody className="text-black max-h-96 overflow-y-auto px-3 md:px-10">
                    <section className="flex flex-col gap-4">
                        <h2 className="text-lg font-bold">Rango Precios (Por Noche)</h2>
                        <div className="pb-1 px-6">
                            <label htmlFor="minRange" className="text-sm">Valor Mínimo</label>                        
                            <input type="range"  id="minRange" min={0} max={1000} value={minValue} onChange={handleMinChange} className="appearance-none bg-red-300 h-2 w-full rounded-md outline-none"/>
                            <label htmlFor="maxRange" className="text-sm">Valor Máximo</label>
                            <input type="range"  id="maxRange" min={0} max={1000} value={maxValue} onChange={handleMaxChange} className="appearance-none bg-red-300 h-2 w-full rounded-md outline-none"/>
                        </div>                        
                        <div className="flex flex-col gap-2 md:flex-row md:gap-4 px-4">
                            <Input label="$ Mínimo" min={0} max={1000} value={minValue} onChange={handleMinChange}/>
                            _
                            <Input label="$ Máximo" min={0} max={1000} value={maxValue} onChange={handleMaxChange}/>
                        </div>                       
                    </section>
                    <section className="mt-10">
                        <h2 className="text-lg font-bold pb-2">Tipo de Propiedad</h2>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 justify-items-center">
                            <Button variant="outlined" className={getButtonClassName('HOUSE')} onClick={() => handleTypeSelection('HOUSE')}> <FontAwesomeIcon icon={faHouse} size="xl"/>Casa</Button>

                            <Button variant="outlined" className={getButtonClassName('APARTMENT')} onClick={() => handleTypeSelection('APARTMENT')}> <FontAwesomeIcon icon={faBuilding} size="xl" />Departamento</Button>

                            <Button variant="outlined" className={getButtonClassName('GUEST_HOUSE')} onClick={() => handleTypeSelection('GUEST_HOUSE')}> <FontAwesomeIcon icon={faWarehouse} size="xl" />Casa de huéspedes</Button>

                            <Button variant="outlined" className={getButtonClassName('HOTEL')} onClick={() => handleTypeSelection('HOTEL')}> <FontAwesomeIcon icon={faHotel} size="xl" />Hotel</Button>
                        </div>
                    </section>
                    <section className="mt-10">
                        <h2 className="text-lg font-bold pb-2">Habitaciones y Camas</h2>
                        <div className="px-4 md:px-8">
                            <h3>Dormitorios</h3>
                            <div className="flex flex-wrap gap-2 md:gap-4">
                                <Radio name="rooms" label="Cualquiera" ripple={true} checked={selectedRooms === 'cualquiera'} onChange={() => handleRoomSelection('cualquiera')}/>
                                <Radio name="rooms" label="1" ripple={true} checked={selectedRooms === '1'} onChange={() => handleRoomSelection('1')}/>
                                <Radio name="rooms" label="2" ripple={true} checked={selectedRooms === '2'} onChange={() => handleRoomSelection('2')}/>
                                <Radio name="rooms" label="3" ripple={true} checked={selectedRooms === '3'} onChange={() => handleRoomSelection('3')}/>
                                <Radio name="rooms" label="4" ripple={true} checked={selectedRooms === '4'} onChange={() => handleRoomSelection('4')}/>
                                <Radio name="rooms" label="5" ripple={true} checked={selectedRooms === '5'} onChange={() => handleRoomSelection('5')}/>
                                <Radio name="rooms" label="6+" ripple={true} checked={selectedRooms === '6+'} onChange={() => handleRoomSelection('6+')}/> 
                            </div>                          
                        </div>
                        <div className="px-4 md:px-8">
                            <h3>Camas</h3>
                            <div className="flex flex-wrap gap-2 md:gap-4">
                                <Radio name="beds" label="Cualquiera" ripple={true} checked={selectedBeds === 'cualquiera'} onChange={() => handleBedSelection('cualquiera')} />
                                <Radio name="beds" label="1" ripple={true} checked={selectedBeds === '1'} onChange={() => handleBedSelection('1')} />
                                <Radio name="beds" label="2" ripple={true} checked={selectedBeds === '2'} onChange={() => handleBedSelection('2')}/>
                                <Radio name="beds" label="3" ripple={true} checked={selectedBeds === '3'} onChange={() => handleBedSelection('3')}/>
                                <Radio name="beds" label="4" ripple={true} checked={selectedBeds === '4'} onChange={() => handleBedSelection('4')}/>
                                <Radio name="beds" label="5" ripple={true} checked={selectedBeds === '5'} onChange={() => handleBedSelection('5')}/>
                                <Radio name="beds" label="6+" ripple={true} checked={selectedBeds === '6+'} onChange={() => handleBedSelection('6+')}/>
                            </div>  
                        </div>
                        <div className="px-4 md:px-8">
                            <h3>Baños</h3>
                            <div className="flex flex-wrap gap-2 md:gap-4">
                                <Radio name="baths" label="Cualquiera" ripple={true} checked={selectedBaths === 'cualquiera'} onChange={() => handleBathSelection('cualquiera')}/>
                                <Radio name="baths" label="1" ripple={true} checked={selectedBaths === '1'} onChange={() => handleBathSelection('1')}/>
                                <Radio name="baths" label="2" ripple={true} checked={selectedBaths === '2'} onChange={() => handleBathSelection('2')}/>
                                <Radio name="baths" label="3" ripple={true} checked={selectedBaths === '3'} onChange={() => handleBathSelection('3')}/>
                                <Radio name="baths" label="4" ripple={true} checked={selectedBaths === '4'} onChange={() => handleBathSelection('4')}/>
                                <Radio name="baths" label="5" ripple={true} checked={selectedBaths === '5'} onChange={() => handleBathSelection('5')}/>
                                <Radio name="baths" label="6+" ripple={true} checked={selectedBaths === '6+'} onChange={() => handleBathSelection('6+')}/>
                            </div>                            
                        </div>                        
                    </section>
                    <section className="mt-10">
                        <h2 className="text-lg font-bold pb-2">Servicios</h2> 
                        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3">
                            <Checkbox id="WIFI" label="Wifi" ripple={true} checked={checkboxes.WIFI} onChange={handleCheckboxChange}/>
                            <Checkbox id="KITCHEN" label="Cocina" ripple={true}checked={checkboxes.KITCHEN} onChange={handleCheckboxChange} />  
                            <Checkbox id="WASHING_MACHINE" label="Lavarropas" ripple={true} checked={checkboxes.WASHING_MACHINE} onChange={handleCheckboxChange}/>
                            <Checkbox id="AIR_CONDITIONER" label="Aire Acondicionado" ripple={true} checked={checkboxes.AIR_CONDITIONER} onChange={handleCheckboxChange}/>  
                            <Checkbox id="HEATING" label="Calefacción" ripple={true} checked={checkboxes.HEATING} onChange={handleCheckboxChange}/>  
                            <Checkbox id="SWIMMING_POOL" label="Pileta" ripple={true} checked={checkboxes.SWIMMING_POOL} onChange={handleCheckboxChange}/>  
                            <Checkbox id="PETS_ALLOWED" label="Permite Mascotas" ripple={true} checked={checkboxes.PETS_ALLOWED} onChange={handleCheckboxChange}/>  
                            <Checkbox id="PARKING_LOT" label="Estacionamiento" ripple={true} checked={checkboxes.PARKING_LOT} onChange={handleCheckboxChange}/>  
                            <Checkbox id="CRADLE" label="Cuna" ripple={true} checked={checkboxes.CRADLE} onChange={handleCheckboxChange}/>  
                            <Checkbox id="GRILL" label="Parrilla" ripple={true} checked={checkboxes.GRILL} onChange={handleCheckboxChange}/>  
                            <Checkbox id="BREAKFAST" label="Desayuno" ripple={true} checked={checkboxes.BREAKFAST} onChange={handleCheckboxChange}/>  
                            <Checkbox id="SMOKING_ALLOWED" label="Se permite fumar" ripple={true} checked={checkboxes.SMOKING_ALLOWED} onChange={handleCheckboxChange}/>
                            <Checkbox id="EARLY_CANCELLATION" label="Cancelación Anticipada" ripple={true} checked={checkboxes.EARLY_CANCELLATION} onChange={handleCheckboxChange}/>   
                        </div>                                       
                    </section>
                </DialogBody>
                <DialogFooter className="flex justify-between">
                    <Button variant="text" color="blue-gray" onClick={clearFilters}>
                        <span>Borrar Filtros</span>
                    </Button>
                    <div>
                        <Button variant="text" color="red" onClick={handleOpen} className="mr-1"
                        >
                            <span>Cerrar</span>
                        </Button>
                        <Button variant="gradient" color="red" onClick={handleFilters}>
                            <span>Filtrar</span>
                        </Button>
                    </div>
                </DialogFooter>
            </Dialog>
        </>
    )
};

