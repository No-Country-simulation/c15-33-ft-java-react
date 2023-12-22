const apiUrl = 'http://149.50.133.215:80';

export async function login(userData) {
    try {
        const response = await fetch(apiUrl+"/auth/login", {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(userData)
        })

        if(response.ok){
            const data = await response.json()
            localStorage.setItem('token', data.token);
            console.log('Inicio de sesión exitoso. Token JWT guardado.');
        } else {
            console.error('Error al iniciar sesión:', response.statusText);
        }
        
        } catch (error) {
            console.error('Error de red:', error);
        }
    
}

export async function register(userData) {
    
    try {
        const response = await fetch(apiUrl+"/auth/register", {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(userData)
        })

        if(response.ok){
            const data = await response.json()
            localStorage.setItem('token', data.token);
            console.log('Registro de usuario exitoso. Usuario guardado.');
        } else {
            console.error('Error al registrar usuario:', response.statusText);
        }
        
        } catch (error) {
            console.error('Error de red:', error);
        }
    
}

export function logout() {
    if (localStorage.getItem('token')) {
        localStorage.removeItem('token');
        console.log('Sesión cerrada correctamente.')
    }
}

export async function submitProperty(formData) {
    const token = localStorage.getItem('token') ? localStorage.getItem('token') : ''

    try {
        const form = new FormData();

        for (const key in formData) {
            const value = formData[key];

            if (key === 'images' && Array.isArray(value)) {
                value.forEach((imageObject, index) => {
                    const file = imageObject.file;

                    if (file instanceof File) {
                        form.append('images', file);
                    }
                });
            } else if (key === 'serviceTypes' && Array.isArray(value)) {
                const selectedServices = value.map(service => service.toString());
                form.append('services', selectedServices.join(','));
            } else if (value instanceof File) {
                form.append(key, value);
            } else if (Array.isArray(value)) {
                value.forEach((item, index) => {
                    if (item instanceof File) {
                        form.append(`${key}[${index}]`, item);
                    } else {
                        form.append(`${key}[${index}]`, item.toString());
                    }
                });
            } else if (typeof value === 'string' || typeof value === 'number') {
                form.append(key, value.toString());
            }
        }

        const response = await fetch(`${apiUrl}/api/property`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`
            },
            body: form
        });

        if (!response.ok) {
            throw new Error();
        }

    } catch (error) {
        console.error('There was an error:', error);
    }
}

export function forceLogout () {
    logout()
}

export async function updateUserData (setUser, username) {
    const token = localStorage.getItem('token') ? localStorage.getItem('token') : ''

    try {
        const response = await fetch(`${apiUrl}/api/user/username/${username}`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        })

        if(response.ok){
            const data = await response.json();
            setUser(data);
        } else {
            if(response.status === 403){
                forceLogout()
            }
            console.error('error de respuesta');
        }
        
        } catch (error) {
            console.error('Error de red:', error);
        }
}

export async function updateUser( formData, id ) {
    const token = localStorage.getItem('token') ? localStorage.getItem('token') : ''

    try {
        const response = await fetch(`${apiUrl}/api/user/${id}`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`
            },
            body: formData
        });

        if (response.ok) {
            const data = await response.json();
            return data;
        }
    } catch (error) {
        console.error('Error de red:', error);
    }
}

export async function deleteUser (id) {
    const token = localStorage.getItem('token') ? localStorage.getItem('token') : ''
    try {
        const response = await fetch(`${apiUrl}/api/user/${id}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },            
        });
        

        if (!response.ok) {
            throw new Error();
        }

    } catch (error) {
        console.error('There was an error:', error);
    }
}

export async function getAllUsers () {
    const token = localStorage.getItem('token') ? localStorage.getItem('token') : ''
    try {
        const response = await fetch(`${apiUrl}/api/user`, {
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

export async function getUser (username) {
    const token = localStorage.getItem('token') ? localStorage.getItem('token') : ''

    try {
        const response = await fetch(`${apiUrl}/api/user/username/${username}`, {
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

export async function getAllProperties () {
    try {
        const response = await fetch(`${apiUrl}/api/property`, {
            method: 'GET',
            headers: {
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

export async function getProperty (id) {
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
export async function getPropertiesByUserId (userId) {
    const token = localStorage.getItem('token') ? localStorage.getItem('token') : ''
    try {
        const response = await fetch(`${apiUrl}/api/property/user/${userId}`, {
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

export async function deleteProperty (id) {
    const token = localStorage.getItem('token') ? localStorage.getItem('token') : ''
    try {
        const response = await fetch(`${apiUrl}/api/property/${id}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
        });
        
        if (!response.ok) {
            throw new Error();
        }


    } catch (error) {
        console.error('There was an error:', error);
    }
}

export async function getImageUrlById (id) {
    const token = localStorage.getItem('token') ? localStorage.getItem('token') : ''

    try {
        const response = await fetch(`${apiUrl}/api/img/${id}`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        })

        if(response.ok){
            const blob = await response.blob();
            const imageUrl = URL.createObjectURL(blob);
            console.log('URL de la imagen:', imageUrl);
            return imageUrl;
        } else {
            console.error('error de respuesta');
        }
        
        } catch (error) {
            console.error('Error de red:', error);
        }
}
