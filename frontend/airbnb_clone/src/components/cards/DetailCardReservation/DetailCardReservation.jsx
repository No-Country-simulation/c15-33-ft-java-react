import { DetailCardButton } from "../";

export const DetailCardReservation = ({totalPrice, value, id}) => {
  return ( 
    <div 
      className="
      bg-white 
        rounded-xl 
        border-[1px]
        border-neutral-200 
        overflow-hidden"
    >
      <div className="flex flex-row items-center gap-1 p-4">
        <div className="text-2xl font-semibold">
          $ {value}
        </div>

        <div className="font-light text-neutral-600">
          la noche
        </div>
      </div>
      <hr />

      <div className="p-4">
        <DetailCardButton id={id} />
      </div>
      <hr />

      <div 
        className="
          p-4 
          flex 
          flex-row 
          items-center 
          justify-between
          font-semibold
          text-lg"
      >
        <div>
          Total
        </div>
        
        <div>
          $ {totalPrice}
        </div>
      </div>
    </div>
  );
}
