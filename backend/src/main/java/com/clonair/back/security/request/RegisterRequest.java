package com.clonair.back.security.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Este DTO se utiliza cuando el cliente envía una solicitud para registrar un nuevo usuario.
 * El controlador AuthController utiliza este objeto para deserializar los datos proporcionados por el cliente
 * y se pasa al servicio de autenticación (AuthService) para crear un nuevo usuario en la base de datos.
 * */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {

    String username;
    String password;
    String firstname;
    String lastname;
    String country;
    String role;
    String description;
    String contact;

}

