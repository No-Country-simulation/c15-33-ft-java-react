import { faChevronDown, faMagnifyingGlass, faTrashCan } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  Card,
  CardHeader,
  Input,
  Typography,
  Button,
  CardBody,
  Chip,  
  Tabs,
  TabsHeader,
  Tab,  
  IconButton,
  Tooltip,
  Dialog,
  DialogHeader,
  DialogBody,
  DialogFooter,  
} from "@material-tailwind/react";
import { useEffect, useState } from "react";
import {  deleteProperty,  deleteUser, getAllUsers, getPropertiesByUserId } from "../../services/apiRequests";
 
const TABS = [
  {
    label: "Todos",
    value: "all",
  },
  {
    label: "User",
    value: "USER",
  },
  {
    label: "Owner",
    value: "OWNER",
  },
];
 
const TABLE_HEAD = ["Username", "Tipo Usuario", "UserId", "Contacto", "Country", "Opciones"];

const TABLE_PROPS_HEAD = ["Título", "PropertyID", "Owner", "Status", ""];

export const AdminPanel = () => {
  const [searchText, setSearchText] = useState('');
  const [activeTab, setActiveTab] = useState('all');
  const [openPropList, setOpenPropList] = useState(false);
  const [usersData, setUsersData] = useState([]);
  const [filteredUsers, setFilteredUsers] = useState([]);
  const [openAlert, setOpenAlert] = useState(false);
  const [userProperties, setUserProperties] = useState([]);
  const [openPropAlert, setOpenPropAlert] = useState(false);
 
  const handleOpenAlert = () => setOpenAlert(!openAlert);
  const handleOpenPropAlert = () => setOpenPropAlert(!openPropAlert);

  const handleOpenPropList = (userId) => {
    setOpenPropList(!openPropList);    
    if (!openPropList) {      
      fetchUserProperties(userId);
    }
  };

  const handleDeleteUser = async (id) => {
    try {
        await deleteUser(id);        
        const updatedUsers = await getAllUsers();
        setUsersData(updatedUsers);
    } catch (error) {
        console.error('Error deleting user:', error);
    }
  };

  const handleDeleteProperty = async (propertyId, userId) => {
    try {      
      await deleteProperty(propertyId);      
      fetchUserProperties(userId);
    } catch (error) {
      console.error('Error al eliminar la propiedad:', error);
    }
  };

  const fetchUserProperties = async (userId) => {
    try {
      const properties = await getPropertiesByUserId(userId);      
      setUserProperties(properties);
    } catch (error) {
      console.error('Error al obtener propiedades:', error);
    }
  };

  const fetchData = async () => {
    try {
      const data = await getAllUsers();
      if (data) {
        console.log('Usuarios recibidos:', data);
        setUsersData(data);
      } else {
        console.error('No se recibieron datos de usuarios.');
      }
    } catch (error) {
      console.error('Error al obtener usuarios:', error);
    }
  };
 
   useEffect(() => {
    fetchData();
  }, []);  

  useEffect(() => {    
    const filtered = usersData.filter((row) => {
      const isMatchingSearch = (row.firstname.toLowerCase()|| row.lastname.toLowerCase()).includes(searchText.toLowerCase());
      
      if (activeTab === 'all') {
        return isMatchingSearch;
      } else if (activeTab === 'USER' && row.role === 'USER') {
        return isMatchingSearch;
      } else if (activeTab === 'OWNER' && row.role === 'OWNER') {
        return isMatchingSearch;
      }
  
      return false;
    });

    setFilteredUsers(filtered);
  }, [usersData, searchText, activeTab]);

  return (
    <Card className="h-full w-full">
      <CardHeader floated={false} shadow={false} className="rounded-none flex flex-col gap-2 px-2">        
        <div className="p-1 flex justify-center">          
          <Typography variant="h5" color="blue-gray">
            Panel de Administración de Usuarios
          </Typography>                           
        </div>
        <section className="flex flex-col sm:flex-row justify-between gap-2">
          <div className="w-1/2 md:w-72">
              <Input
                label="Buscar"
                icon={<FontAwesomeIcon icon={faMagnifyingGlass} className="h-5 w-5" />}
                value={searchText}
                onChange={(e) => setSearchText(e.target.value)}
              />
            </div>        
          <div className="w-1/2 md:w-72 min-w-fit">
            <Tabs value={activeTab} onChange={(value) => setActiveTab(value)}>  
              <TabsHeader>            
                {TABS.map(({ label, value }) => (
                  <Tab 
                    key={value} 
                    value={value} 
                    onClick={() => setActiveTab(value)}>
                    &nbsp;&nbsp;{label}&nbsp;&nbsp;
                  </Tab>
                ))}
                </TabsHeader>
            </Tabs>          
          </div>
        </section>
      </CardHeader>
      <CardBody className="overflow-auto px-2">
        <table className="w-full min-w-max table-auto text-left">
          <thead>
            <tr>
              {TABLE_HEAD.map((head, index) => (
                <th
                  key={head}
                  className="border-y border-blue-gray-100 bg-blue-gray-50/50 p-4 transition-colors hover:bg-blue-gray-50">
                  <Typography
                    variant="small"
                    color="blue-gray"
                    className="flex items-center justify-between gap-2 font-normal leading-none opacity-70">
                    {head}{" "}
                    {index !== TABLE_HEAD.length - 1 && (
                      <FontAwesomeIcon icon={faChevronDown} className="h-4 w-4"/>
                    )}
                  </Typography>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filteredUsers?.map(
              ({ firstname, lastname, role, username, id, contact, country }, index) => {
                const isLast = index === TABLE_HEAD.length - 1;
                const classes = isLast
                  ? "p-4"
                  : "p-4 border-b border-blue-gray-50"; 
                return (
                  <tr key={username}>
                    <td className={classes}>
                      <div className="flex items-center gap-3">                        
                        <div className="flex flex-col">
                          <Typography
                            variant="small"
                            color="blue-gray"
                            className="font-normal"
                          >
                            {firstname+" "+lastname}
                          </Typography>
                          <Typography
                            variant="small"
                            color="blue-gray"
                            className="font-normal opacity-70"
                          >
                            {username}
                          </Typography>
                        </div>
                      </div>
                    </td>
                    <td className={classes}>
                      <div className="flex flex-col">
                        <Typography
                          variant="small"
                          color="blue-gray"
                          className="font-normal"
                        >
                          {role}
                        </Typography>                        
                        <Typography
                          variant="small"
                          color="blue-gray"
                          className="font-normal opacity-70">
                            {role==="USER" ? "-" : 
                            <Button variant="text" className="p-1" onClick={()=>handleOpenPropList(id)}>
                              Propiedades
                            </Button>}                            
                            <Dialog open={openPropList}>
                              <DialogHeader>Listado de Propiedades</DialogHeader>
                              <DialogBody>
                                <Card className="h-full w-full overflow-auto">
                                  <table className="w-full min-w-max table-auto text-left">
                                    <thead>
                                      <tr>
                                        {TABLE_PROPS_HEAD.map((head) => (
                                          <th key={head} className="border-b border-blue-gray-100 bg-blue-gray-50 p-4">
                                            <Typography
                                              variant="small"
                                              color="blue-gray"
                                              className="font-normal leading-none opacity-70"
                                            >
                                              {head}
                                            </Typography>
                                          </th>
                                        ))}
                                      </tr>
                                    </thead>
                                    <tbody>
                                      {userProperties==""? <Typography>No hay propiedades registradas</Typography> :userProperties.map(({ title, id,  username, active }) => (
                                        <tr key={id} className="even:bg-blue-gray-50/50">
                                          <td className="p-4">
                                            <Typography variant="small" color="blue-gray" className="font-normal">
                                              {title}
                                            </Typography>
                                          </td>
                                          <td className="p-4">
                                            <Typography variant="small" color="blue-gray" className="font-normal">
                                              {id}
                                            </Typography>
                                          </td>
                                          <td className="p-4">
                                            <Typography variant="small" color="blue-gray" className="font-normal">
                                              {username}
                                            </Typography>
                                          </td>
                                          <td className="p-4">                                            
                                            <Chip
                                              variant="ghost"
                                              size="sm"
                                              value={active ? "activa" : "inactiva"}
                                              color={active ? "green" : "blue-gray"}
                                            />
                                          </td>
                                          <td className="p-4"> 
                                            <Tooltip content="Borrar Propiedad">
                                              <IconButton variant="text" onClick={handleOpenPropAlert}>                        
                                                <FontAwesomeIcon icon={faTrashCan} className="h-4 w-4"/>
                                              </IconButton>
                                            </Tooltip>
                                            <Dialog open={openPropAlert} handler={handleOpenPropAlert}>
                                              <DialogHeader>¿Eliminar propiedad?</DialogHeader>
                                              <DialogBody>
                                                <Typography variant="h5">¿Estás seguro que deseas borrar la propiedad?</Typography>
                                                <Typography variant="h6">Los datos no podrán recuperarse y el usuario deberá volver a registrar la propiedad.</Typography>                            
                                              </DialogBody>
                                              <DialogFooter>
                                                <Button
                                                  variant="text"
                                                  color="red"
                                                  onClick={handleOpenPropAlert}
                                                  className="mr-1"
                                                >
                                                  <span>Cancel</span>
                                                </Button>
                                                <Button variant="gradient" color="green"  onClick={() => handleDeleteProperty(id)} >
                                                  <span>Confirm</span>
                                                </Button>
                                              </DialogFooter>
                                            </Dialog>                                            
                                          </td>
                                        </tr>
                                      ))}
                                    </tbody>
                                  </table>
                                </Card>
                              </DialogBody>
                              <DialogFooter>
                                <Button
                                  variant="text"
                                  color="red"
                                  onClick={handleOpenPropList}
                                  className="mr-1"
                                >
                                  <span>Cancelar</span>
                                </Button>
                                <Button variant="gradient" color="green" onClick={handleOpenPropList}>
                                  <span>Confirmar</span>
                                </Button>
                              </DialogFooter>
                            </Dialog>
                        </Typography>                        
                      </div>
                    </td>
                    <td className={classes}>
                      <div className="w-max">
                      <Typography
                        variant="small"
                        color="blue-gray"
                        className="font-normal"
                      >
                        {id}
                      </Typography>
                      </div>
                    </td>
                    <td className={classes}>
                      <Typography
                        variant="small"
                        color="blue-gray"
                        className="font-normal"
                      >
                        {contact?contact:"-"}
                      </Typography>
                    </td>
                    <td className={classes}>
                      <Typography
                        variant="small"
                        color="blue-gray"
                        className="font-normal"
                      >
                        {country}                                             
                      </Typography>
                    </td>
                    <td className={classes}> 
                    { role === "ADMIN" ? " " :
                      <>                    
                        <Tooltip content="Borrar Usuario">
                          <IconButton variant="text" onClick={handleOpenAlert}>                      
                            <FontAwesomeIcon icon={faTrashCan} className="h-4 w-4"/>
                          </IconButton>
                        </Tooltip>
                          <Dialog open={openAlert} handler={handleOpenAlert}>
                            <DialogHeader>¿Eliminar usuario?</DialogHeader>
                            <DialogBody>
                              <Typography variant="h5">¿Estás seguro que deseas borrar el usuario?</Typography>
                              <Typography variant="h6">Los datos no podrán recuperarse y el usuario deberá volver a registrarse.</Typography>                            
                            </DialogBody>
                            <DialogFooter>
                              <Button
                                variant="text"
                                color="red"
                                onClick={handleOpenAlert}
                                className="mr-1"
                              >
                                <span>Cancel</span>
                              </Button>
                              <Button variant="gradient" color="green" onClick={() => handleDeleteUser(id)}>
                                <span>Confirm</span>
                              </Button>
                            </DialogFooter>
                          </Dialog>
                      </>
                    }                    
                    </td>
                  </tr>
                );
              },
            )}
          </tbody>
        </table>
      </CardBody>      
    </Card>
  );
};

