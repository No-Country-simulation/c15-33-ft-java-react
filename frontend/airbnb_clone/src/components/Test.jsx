import { Button } from "@material-tailwind/react"
import { useAuth } from "../context/authContext";
import { getAllProperties } from "../services/apiRequests";


export const Test = () => {
    const apiUrl = 'http://149.50.133.215:80';
    const token = localStorage.getItem('token') ? localStorage.getItem('token') : ''

    const { user, setUser } = useAuth()


      const property = {
        "title": "Titulo",
        "description": "Descripcion",
        "images": [],
        "value": "123",
        "location": "Antarctica",
        "category": "casa",
        "subCategory": "cabana",
        "bathroom": "2",
        "bed": "5",
        "bedroom": "1",
        "serviceTypes": [
            "cocina",
            "mascotas"
        ],
        "permanent_availability": "true",
        "availability": [],
        "active": "true",
        "user": "user_owner_placeholder"
    }

      const getUsers = async () => {
        try {
            const response = await fetch(`${apiUrl}/api/user`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            })
    
            if(response.ok){
                const data = await response.json()
                console.log(data)
            } else {
                console.error('error de respuesta');
            }
            
            } catch (error) {
                console.error('Error de red:', error);
            }
      }

      const id = "1681b20b-813b-40ca-ad21-47b6c5583dee"

       async function getProperty (id) {
        const token = localStorage.getItem('token') ? localStorage.getItem('token') : ''
        try {
            const response = await fetch(`${apiUrl}/api/property/${id}`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            })
    
            if(response.ok){
                const data = await response.json()
                return data
            } else {
                console.error('error de respuesta');
            }
            
            } catch (error) {
                console.error('Error de red:', error);
            }
    }

    

    return (
        <>
            {/* <Button onClick={getUsers}>Get Data</Button>
            <Button onClick={() => getProperty(id)}>Get Property</Button>
            <Button onClick={getAllProperties}>Get Properties</Button> */}

        </>
    )
}