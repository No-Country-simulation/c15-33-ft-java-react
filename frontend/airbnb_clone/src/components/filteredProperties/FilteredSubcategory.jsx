import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Spinner } from "@material-tailwind/react";
import { Container, EmptyState, HostCardItem } from "..";
import { getAllProperties } from "../../services/apiRequests";

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

const FilteredSubcategory = () => {
    const [properties, setProperties] = useState([]);
    const [loading, setLoading] = useState(true);
    const { text } = useParams();
    
   
    useEffect(() => {        
        const propertiesFetch = async () => {
            try {
                const properties = await getAllProperties();
                const subcategoryValue = subcategories.find(sub => sub.name === text)?.value;
                if (subcategoryValue) {
                    const filteredProps = properties.filter(property => property.subCategory === subcategoryValue);                    
                    setProperties(filteredProps);
                    setLoading(false);  
                }               
            } catch (error) {
                console.error('Error al obtener propiedades:', error);
                setLoading(false);
            }
        };

        propertiesFetch();
    }, [text]);
   
   
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

export default FilteredSubcategory;