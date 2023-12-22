

export const DetailCardButton = (id) => {
  console.log(id);
    return ( 
        <button
          className="
            relative
            disabled:opacity-70
            rounded-lg
            hover:opacity-80
            transition
            w-full
            bg-pink-500
            border-pink-500
            text-white
            text-md
            py-3
            font-semibold
            border-2
          "
        >
          Reservar
        </button>
       );
}
