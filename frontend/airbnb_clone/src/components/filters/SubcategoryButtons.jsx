import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { getAllProperties } from "../../services/apiRequests";


export const SubcategoryButtons = ({ icon, text }) => {
    const getButtonClassName = "flex flex-col items-center hover:text-gray-900 border-b-4 border-b-white hover:border-b-gray-900 p-2";
    
    const subcategories = [
        {
            name: "Playa",
            value: "BEACH"
        },
        {
            name: "Lago",
            value: "LAKE"
        },
        {
            name: "Montaña",
            value: "MOUNTAIN"
        },
        {
            name: "Campo",
            value: "COUNTRYSIDE"
        },
        {
            name: "Pileta",
            value: "SWIMMING_POOL"
        },
        {
            name: "Urbana",
            value: "URBAN"
        },
        {
            name: "Tropical",
            value: "TROPICAL"
        },
        {
            name: "Cabaña",
            value: "CABIN"
        },
        {
            name: "Camping",
            value: "CAMPING"
        }
    ];
    
    const handleButtonClick = async () => {
        try {
            const properties = await getAllProperties();
            const subcategoryValue = subcategories.find(sub => sub.name === text)?.value;
            if (subcategoryValue) {
                const filteredProperties = properties.filter(property => property.subCategory === subcategoryValue);
                console.log(filteredProperties);
            }
        } catch (error) {
            console.error('Error al obtener propiedades:', error);
        }
    };

    return (
        <button className={getButtonClassName} onClick={handleButtonClick}>
            <FontAwesomeIcon icon={icon} className="h-6" />
            {text}
        </button>
    );
};
