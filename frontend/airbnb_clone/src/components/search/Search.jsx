import { useEffect, useRef, useState } from 'react';
import { Button, Typography } from '@material-tailwind/react';
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
    faPerson,    
    faMapLocationDot,
    faMagnifyingGlass
  } from "@fortawesome/free-solid-svg-icons";
import { countries } from 'countries-list';
import { getAllProperties } from '../../services/apiRequests';

export const Search = () => {    
    const queryParams = new URLSearchParams(location.search);    

    const [destination, setDestination] = useState("");  
    const [openOptions, setOpenOptions] = useState(false);
    const [options, setOptions] = useState({
        adult: parseInt(queryParams.get('adults'), 10) || 1,
        children: parseInt(queryParams.get('children'), 10) || 0,
        room: parseInt(queryParams.get('rooms'), 10) || 1,
    });
    const [emptyInput, setEmptyInput] = useState(false);
   

    const handleOption = (name, operation) => {
        setOptions((prev) => {
        return {
            ...prev,
            [name]: operation === "i" ? options[name] + 1 : options[name] - 1,
        };
        });
    }; 

    const optionsRef = useRef(null);
  
    useEffect(() => {
      const handleClickOutside = (event) => {
        if (            
            (optionsRef.current && !optionsRef.current.contains(event.target))
          ) {            
            setOpenOptions(false);          
          } 
      };
  
      document.addEventListener('mousedown', handleClickOutside);
  
      return () => {
        document.removeEventListener('mousedown', handleClickOutside);
      };
    }, []);
  
    const handleSearch = async () => {
        if (destination.trim() === '' ) {
            setEmptyInput(true);
            return;
        }  
       
        try {
            const properties = await getAllProperties();

            const filteredProperties = properties.filter(property => {                
                const matchesCountry = property.location.country === destination;               
                const matchesRooms = property.bedroom >= options.room;
                const totalGuests = options.adult + options.children;                
                const enoughBeds = property.bed >= totalGuests;
                
                return matchesCountry && matchesRooms && enoughBeds;
            });            
        
            console.log(filteredProperties);
        
        } catch (error) {
            console.error('Error al obtener propiedades:', error);
        }
    };
    
    const countryNames = (Object.values(countries).map((country) => country.name)).sort();

    return (
        <div className="flex flex-col justify-center absolute z-10 bg-white box-border mt-32 ml-20 shadow-md hover:shadow-lg border-2 border-gray-300 rounded-xl"> 
                <div className="h-30 flex border items-center justify-around p-3 rounded-xl gap-4 text-sm">
                    <div className="flex items-center gap-2.5">   
                        <FontAwesomeIcon icon={faMapLocationDot} />
                       <select value={destination} onChange={(e) => setDestination(e.target.value)} className="border-0 outline-0 w-20 md:w-28 cursor-pointer text-gray-400">
                            <option className="text-gray-600">País</option>
                            {countryNames.map((countryName) => (
                                <option key={countryName} value={countryName} className="text-gray-600">
                                    {countryName}
                                </option>
                            ))}
                        </select>
                    </div>                   
                    <div className="flex items-center gap-2.5" ref={optionsRef}> 
                        <FontAwesomeIcon icon={faPerson} />
                        <div className="flex justify-center"> 
                            <span className="md:hidden cursor-pointer text-gray-400" onClick={() => setOpenOptions(!openOptions)}>Huéspedes</span>     
                            <span
                            onClick={() => setOpenOptions(!openOptions)}
                            className="cursor-pointer text-gray-400 hidden md:inline"
                            >{`${options.adult} adultos · ${options.children} menores · ${options.room} habitaciones`}</span>
                            {openOptions && (
                            <div className="z-10 absolute mt-10 text-gray-700 shadow-lg bg-white">
                                <div className="w-52 flex justify-between m-3">
                                    <span className="flex items-center px-1.5">Adultos</span>
                                    <div className="flex items-center gap-2.5 text-black">
                                        <Button
                                        disabled={options.adult <= 1}
                                        className="w-8 h-8 border-2 cursor-pointer bg-gray-300 text-black -p-2 disabled:cursor-not-allowed"
                                        onClick={() => handleOption("adult", "d")}
                                        >
                                        -
                                        </Button>
                                        <span>
                                        {options.adult}
                                        </span>
                                        <Button
                                        className="w-8 h-8 border-2 cursor-pointer bg-gray-300 text-black -p-2"
                                        onClick={() => handleOption("adult", "i")}
                                        >
                                        +
                                        </Button>
                                    </div>
                                </div>
                                <div className="w-52 flex justify-between m-3">
                                    <span className="flex items-center px-1.5">Menores</span>
                                    <div className="flex items-center gap-2.5 text-black">
                                        <Button
                                        disabled={options.children <= 0}
                                        className="w-8 h-8 border-2 cursor-pointer bg-gray-300 text-black -p-2 disabled:cursor-not-allowed"
                                        onClick={() => handleOption("children", "d")}
                                        >
                                        -
                                        </Button>
                                        <span>
                                        {options.children}
                                        </span>
                                        <Button
                                        className="w-8 h-8 border-2 cursor-pointer bg-gray-300 text-black -p-2"
                                        onClick={() => handleOption("children", "i")}
                                        >
                                        +
                                        </Button>
                                    </div>
                                </div>
                                <div className="flex justify-between m-3">
                                    <span className="flex items-center px-1.5">Habitaciones</span>
                                    <div className="flex items-center gap-2.5 text-black">
                                        <Button
                                        disabled={options.room <= 1}
                                        className="w-8 h-8 border-2 cursor-pointer bg-gray-300 text-black -p-2"
                                        onClick={() => handleOption("room", "d")}
                                        >
                                        -
                                        </Button>
                                        <span>
                                        {options.room}
                                        </span>
                                        <Button
                                        className="w-8 h-8 border-2 cursor-pointer bg-gray-300 text-black -p-2"
                                        onClick={() => handleOption("room", "i")}
                                        >
                                        +
                                        </Button>
                                    </div>
                                </div>
                            </div>
                            )}
                        </div>
                    </div>
                    <div className="flex items-center gap-2.5">
                        <Button className="bg-red-500 md:hidden w-10 pl-3.5" onClick={handleSearch}><FontAwesomeIcon icon={faMagnifyingGlass} /></Button>
                        <Button className="bg-red-500 hidden md:inline w-20 p-2" onClick={handleSearch}>Search</Button>
                    </div>
                </div>
                {emptyInput ?
                <div className="h-fit p-1 text-center">
                    <Typography className="" variant="small" color="red">
                        * Faltan datos para realizar la búsqueda *
                    </Typography>
                </div> 
                : "" }
        </div>
    );  
};

