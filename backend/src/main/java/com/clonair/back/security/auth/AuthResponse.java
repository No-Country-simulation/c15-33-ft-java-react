package com.clonair.back.security.auth;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * AuthResponse es una clase de transferencia de datos que encapsula el token JWT como respuesta a una solicitud de autenticación o registro.
 * */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {

    String token;
    List<String> role;
}

