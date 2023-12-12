import { useParams } from "react-router-dom";
import { Container } from "../../shared";
import { DetailCardHead, DetailCardInfo, DetailCardReservation } from "..";

export const DetailContainerCard = () => {
  const id = useParams();
  console.log(id);

  return ( 
    <Container>
      <div 
        className="
          max-w-screen-lg 
          mx-auto
        "
      >
        <div className="flex flex-col gap-6">
          <DetailCardHead
            location={"Nueva York, Estados Unidos"}
            address={"Tokio, Japón"}
            image={"https://source.unsplash.com/random?q=hotel%20paris"}
          />
          <div 
            className="
              grid 
              grid-cols-1 
              md:grid-cols-7 
              md:gap-10 
              mt-6
            "
          >
            <DetailCardInfo
              userName={"Kasey"}
              description={"Escápese de todo en nuestra cabaña de 1969 bellamente renovada, ubicada en las montañas de Nuevo México, escondida en la pequeña ciudad de Angel Fire. Todas esas vibraciones de la cabaña desde fuera, pero modernas desde dentro. Nuestro 2 dormitorios, 2 baños recién actualizado cabaña alpina está situado entre el esquí, ciclismo, golf y senderismo. Tenemos todo lo que necesitas y quieres para disfrutar de la estancia más relajante de tus vacaciones en la montaña."}
              roomCount={2}
              guestCount={6}
              bathroomCount={2}
              locationValue={250}
              label={"Favorito entre los huespedes"}
              littleDescription={"Uno de los alojamientos preferidos entre los huéspedes en Airbnb"}
            />
            <div 
              className="
                order-first 
                mb-10 
                md:order-last 
                md:col-span-3
              "
            >
              <DetailCardReservation
                price={100}
                totalPrice={350}
              />
            </div>
          </div>
        </div>
      </div>
    </Container>
   );
}
