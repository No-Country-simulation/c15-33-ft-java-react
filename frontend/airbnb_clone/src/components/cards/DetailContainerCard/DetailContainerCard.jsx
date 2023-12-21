import { useLocation, useParams } from "react-router-dom";
import { Container } from "../../shared";
import { DetailCardHead, DetailCardInfo, DetailCardReservation } from "../";

export const DetailContainerCard = () => {

  const id = useParams();
  id

  let { state } = useLocation();
  const {description, country, value, image, bedroom, bed, bathroom} = state;

  let totalPrice = value;

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
            description={description}
            country={country}
            image={image}
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
              description={description}
              bedroom={bedroom}
              bed={bed}
              bathroom={bathroom}
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
                value={value}
                totalPrice={totalPrice}
              />
            </div>
          </div>
        </div>
      </div>
    </Container>
   );
}
