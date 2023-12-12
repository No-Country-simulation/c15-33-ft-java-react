import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { Filters } from "../filters";
import { faCampground, faCity, faHouseChimney, faHouseFloodWater, faMountainCity, faSun, faUmbrellaBeach, faWarehouse, faWaterLadder } from "@fortawesome/free-solid-svg-icons";


const NavBarFilters = () => {
    const getButtonClassName =  "flex flex-col items-center hover:text-gray-900 border-b-4 border-b-white hover:border-b-gray-900 p-2";
      
    return (
        <div className="box-border py-3 px-8 flex justify-between items-center gap-4 border-2 w-full">
            <div className="border border-gray-300 rounded-lg text-md px-5 py-2 w-fit flex gap-8 overflow-auto min-w-11/12 text-gray-600">
                <button className={getButtonClassName}><FontAwesomeIcon icon={faUmbrellaBeach} className="h-6"/>Playa</button>
                <button className={getButtonClassName}><FontAwesomeIcon icon={faHouseFloodWater} className="h-6"/>Lago</button>
                <button className={getButtonClassName}><FontAwesomeIcon icon={faMountainCity} className="h-6"/>Montaña</button>
                <button className={getButtonClassName}><FontAwesomeIcon icon={faWarehouse} className="h-6"/>Campo</button>
                <button className={getButtonClassName}><FontAwesomeIcon icon={faWaterLadder} className="h-6"/>Pileta</button>
                <button className={getButtonClassName}><FontAwesomeIcon icon={faCity} className="h-6"/>Urbana</button>
                <button className={getButtonClassName}><FontAwesomeIcon icon={faSun} className="h-6"/>Tropical</button>
                <button className={getButtonClassName}><FontAwesomeIcon icon={faHouseChimney} className="h-6"/>Cabaña</button>
                <button className={getButtonClassName}><FontAwesomeIcon icon={faCampground} className="h-6"/>Camping</button>            
            </div>
            <Filters/>                 
        </div>
    );
};

export default NavBarFilters;