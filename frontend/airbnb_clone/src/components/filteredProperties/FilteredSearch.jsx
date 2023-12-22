import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { Spinner } from "@material-tailwind/react";
import { Container, EmptyState, HostCardItem } from "..";
import { getAllProperties } from "../../services/apiRequests";


const FilteredSearch = () => {
    const [properties, setProperties] = useState([]);
    const [loading, setLoading] = useState(true);
    
    const location = useLocation();
    const queryParams = new URLSearchParams(location.search);

    const destination = queryParams.get('destination');
    const adults = parseInt(queryParams.get('adults'), 10) || 1;
   const children = parseInt(queryParams.get('children'), 10) || 0;
    const rooms = parseInt(queryParams.get('rooms'), 10) || 1;
   
    useEffect(() => {         
             
        const propertiesFetch = async () => {
            try {
                const properties = await getAllProperties();
                const filteredProperties = properties.filter(property => {                
                    const matchesCountry = property.location.country === destination;               
                    const matchesRooms = property.bedroom >= rooms;
                    const totalGuests = adults + children;                
                    const enoughBeds = property.bed >= totalGuests;
                    
                    return matchesCountry && matchesRooms && enoughBeds;
                });  
                console.log(filteredProperties)
                    setProperties(filteredProperties);
                    setLoading(false);                              
            } catch (error) {
                console.error('Error al obtener propiedades:', error);
                setLoading(false);
            }
        };

        propertiesFetch();
    }, [adults, children, destination, rooms]);
   
   
    if (properties.length === 0) {
      return (
        <div className="grid items-center justify-center h-screen">
          {
            loading
          ? 
            (<Spinner className="h-12 w-12" />)
          :
            (
              <EmptyState
                title={"Alojamientos"}
                subtitle={"No hay ningún alojamiento publicado... ¡por ahora!"}
                showReset={true}
              />
            )
        }
        </div>
      );
    }
  
    return (
      <Container>
        <div className="pt-6 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 2xl:grid-cols-6 gap-8">
            {loading ? 
                  (<div className="grid items-center justify-center h-screen">
                      <Spinner className="h-12 w-12" /></div>)
                : 
                  (properties.map((propertie) => (
                        <Link   key={propertie.id}
                                to={`/property-detail/${propertie.id}`}
                                state={{
                                title: propertie.title,
                                username: propertie.username,
                                category: propertie.category,
                                subCategory: propertie.subCategory,
                                description: propertie.description,
                                value: propertie.value,
                                active: propertie.active,
                                images: propertie.images,
                                location: propertie.location,
                                bathroom: propertie.bathroom,
                                bed: propertie.bed,
                                bedroom: propertie.bedroom,}}>
                            <HostCardItem
                            title={propertie.title}
                            description={propertie.description}
                            location={propertie.location}                        
                            value={propertie.value}
                            images={propertie.images}/>
                        </Link>
                    )
                    )
                  )
            }
          </div>
      </Container>
    )
};

export default FilteredSearch;