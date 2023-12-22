
export const DetailCardCategory = ({category, subCategory, active}) => {
    return ( 
        <div className="flex flex-col gap-6">
            <div className="flex flex-row items-center gap-4">
                <div className="flex flex-col">
                    {/* <div 
                    className="text-lg font-semibold"
                    >
                        {category}
                    </div> */}

                    <div className="
                        flex 
                        flex-row 
                        items-center 
                        gap-4 
                        font-light
                        text-neutral-500"
                        >
                        <div>
                            {category}
                        </div>
                        <div>
                            {subCategory}
                        </div>
                        <div>
                            {
                                active
                                    ?
                                        "Disponible"
                                    :
                                        "No disponible"
                            
                            }
                        </div>
                    </div>

                    {/* <div className="text-neutral-500 font-light mt-1">
                        {description}
                    </div> */}
                </div>
            </div>
        </div>
    );
}
