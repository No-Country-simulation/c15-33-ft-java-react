import { Button } from "@material-tailwind/react";
import { Filters, SubcategoryButtons } from "../filters";
import { faCampground, faCity, faHouseChimney, faHouseFloodWater, faMountainCity, faSun, faUmbrellaBeach, faWarehouse, faWaterLadder } from "@fortawesome/free-solid-svg-icons";
import { Link } from "react-router-dom";

export const NavBarFilters = () => {
    const filtersData = [
        { icon: faUmbrellaBeach, text: "Playa" },
        { icon: faHouseFloodWater, text: "Lago" },
        { icon: faMountainCity, text: "Montaña" },
        { icon: faWarehouse, text: "Campo" },
        { icon: faWaterLadder, text: "Pileta" },
        { icon: faCity, text: "Urbana" },
        { icon: faSun, text: "Tropical" },
        { icon: faHouseChimney, text: "Cabaña" },
        { icon: faCampground, text: "Camping" }
    ];

    return (
        <div className="box-border py-3 px-8 flex justify-between items-center gap-4 border-2 w-full">
            <div className="border border-gray-300 rounded-lg text-md px-5 py-2 w-fit flex gap-8 overflow-auto min-w-11/12 text-gray-600">                
                {filtersData.map((filter, index) => (                    
                    <SubcategoryButtons  key={index} icon={filter.icon} text={filter.text}/>
                ))}   
            </div>  
            {/* Boton Admin y registro de propiedad temporales */} 
            <Link to="/admin-panel">
                <Button variant="text">Admin</Button>
            </Link>     
            <Link to="/account-settings">
                <Button variant="text">Cuenta</Button>
            </Link>  
            {/* Boton Admin y registro de propiedad temporales */}    

            <Filters />
        </div>
    );
};

