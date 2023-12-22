import { Heading } from "../";

export const DetailCardHead = ({image, title, country}) => {
  return ( 
    <>
      <Heading
        title={title}
        subtitle={country}
      />
      <div className="
        w-full
        h-[60vh]
        overflow-hidden
        rounded-xl
        relative"
      >
        <img
          className=" w-full object-cover object-center"
          src={image}
          alt="image"
        />
      </div>
    </>
  );
}
