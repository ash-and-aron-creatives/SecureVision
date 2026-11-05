import { useState } from "react";
import type { FormEvent } from "react";
import { login } from "../api/login";
import type { LoginResponse } from "../types";
import type { ApiRequester } from "../api/types";

export function useLogin(
  apiRequest: ApiRequester,
  onAuthenticated: (data: LoginResponse, rememberMe: boolean) => void,
) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(true);
  const [error, setError] = useState("");

  const handleLogin = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError("");

    try {
      const data = await login(apiRequest, username, password);
      onAuthenticated(data, rememberMe);
      setPassword("");
    } catch (loginError) {
      setError(loginError instanceof Error ? loginError.message : "Unable to connect to the backend.");
    }
  };

  return {
    username,
    setUsername,
    password,
    setPassword,
    showPassword,
    setShowPassword,
    rememberMe,
    setRememberMe,
    error,
    handleLogin,
  };
}
