import { Link } from "react-router-dom";
import { Container, HostCardItem } from "..";

const alojamientos = [
    {
      id: "1as4d",
      location: "Apartamento en el centro",
      address: "Calle 50, Tegucigalpa, Honduras",
      reservationDate:"11-12 de dic",
      price: "200",
      image: "https://source.unsplash.com/random",
    },
    {
      id: 2,
      location: "Hotel Ritz, París, Francia",
      address: "15 Place Vendôme, 75001 París, Francia",
      reservationDate: "20-22 de dic",
      price: "5000",
      image: "https://source.unsplash.com/random?q=hotel%20paris"
    },
    {
      id: 3,
      location: "Nueva York, Estados Unidos",
      address: "Tokio, Japón",
      reservationDate: "23 de dic",
      price: "1000",
      image: "https://source.unsplash.com/random?q=vuelo%20new%20york%20tokio"
    },
    {
      id: 8,
      location: "Trattoria Da Cesare al Casaletto, Roma, Italia",
      address: "Via di Casaletto, 37, 00153 Roma RM, Italia",
      reservationDate: "26 de dic",
      price: "100",
      image: "https://source.unsplash.com/random?q=restaurante%20roma"
    },
    {
      id: 9,
      location: "Gran Cañón, Arizona, Estados Unidos",
      address: "Paseo en helicóptero",
      reservationDate: "27 de dic",
      price: "200",
      image: "https://source.unsplash.com/random?q=paseo%20helicóptero%20gran%20cañón"
    },
    {
      id: 11,
      location: "África",
      address: "Safari de tres días en la sabana africana",
      reservationDate: "29 de dic - 31 de dic",
      price: "2000",
      image: "https://source.unsplash.com/random?q=safari+africano"
    }
  ];

export const CardContainer = () => {
  return (
    <Container>
      <div 
          className="
            pt-6
            grid 
            grid-cols-1 
            sm:grid-cols-2 
            md:grid-cols-3 
            lg:grid-cols-4
            xl:grid-cols-5
            2xl:grid-cols-6
            gap-8
          "
        >
          {alojamientos.map((alojamiento) => (
            <Link key={alojamiento.id} to={`/property-detail/${alojamiento.id}`}>
              <HostCardItem location={alojamiento.location} address={alojamiento.address} reservationDate={alojamiento.reservationDate} price={alojamiento.price} image={alojamiento.image} />
            </Link>
          )
          )}
        </div>
    </Container>
  )
}