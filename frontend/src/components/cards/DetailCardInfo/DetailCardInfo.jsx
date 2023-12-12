import { DetailCardCategory } from "..";

export const DetailCardInfo = ({
    label,
    littleDescription,
    userName,
    description,
    guestCount,
    roomCount,
    bathroomCount,
    locationValue}) => {
    return ( 
        <div className="col-span-4 flex flex-col gap-8">
          <div className="flex flex-col gap-2">
            <div 
              className="
                text-xl 
                font-semibold 
                flex 
                flex-row 
                items-center
                gap-2
              "
            >
              <div>Anfitrión: {userName}</div>
            </div>
            <div className="
                flex 
                flex-row 
                items-center 
                gap-4 
                font-light
                text-neutral-500
              "
            >
              <div>
                {guestCount} huéspedes
              </div>
              <div>
                {roomCount} habitaciones
              </div>
              <div>
                {bathroomCount} baños
              </div>
            </div>
          </div>
          <hr />
            <DetailCardCategory
              label={label}
              littleDescription={littleDescription} 
            />
          <hr />
          <div className="
          text-lg font-light text-neutral-500">
            {description}
          </div>
          <hr />
        </div>
       );
}
