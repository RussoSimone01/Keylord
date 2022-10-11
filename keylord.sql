-- phpMyAdmin SQL Dump
-- version 5.0.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Creato il: Ott 11, 2022 alle 10:34
-- Versione del server: 10.4.11-MariaDB
-- Versione PHP: 7.4.3

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET AUTOCOMMIT = 0;
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `keylord`
--
CREATE DATABASE IF NOT EXISTS `keylord` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE `keylord`;

-- --------------------------------------------------------

--
-- Struttura della tabella `dati`
--

CREATE TABLE `dati` (
  `ID` int(11) NOT NULL,
  `Backup` int(11) DEFAULT NULL,
  `Utente` varchar(255) NOT NULL,
  `SitoApp` varchar(255) NOT NULL,
  `Username` varchar(255) NOT NULL,
  `Password` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------

--
-- Struttura della tabella `sicurezza`
--

CREATE TABLE `sicurezza` (
  `Utente` varchar(255) NOT NULL,
  `Email` varchar(255) DEFAULT NULL,
  `TentativiPassword` int(1) NOT NULL DEFAULT 3,
  `TentativiPIN` int(1) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------

--
-- Struttura della tabella `utenti`
--

CREATE TABLE `utenti` (
  `Utente` varchar(255) NOT NULL,
  `Password` varchar(255) NOT NULL,
  `PasswordSalt` varchar(255) NOT NULL,
  `PIN` varchar(255) DEFAULT NULL,
  `PINSalt` varchar(255) DEFAULT NULL,
  `Backup` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Indici per le tabelle scaricate
--

--
-- Indici per le tabelle `dati`
--
ALTER TABLE `dati`
  ADD PRIMARY KEY (`ID`),
  ADD UNIQUE KEY `Backup` (`Backup`) USING BTREE,
  ADD KEY `Utente` (`Utente`);

--
-- Indici per le tabelle `sicurezza`
--
ALTER TABLE `sicurezza`
  ADD UNIQUE KEY `Email` (`Email`),
  ADD KEY `Utente` (`Utente`);

--
-- Indici per le tabelle `utenti`
--
ALTER TABLE `utenti`
  ADD PRIMARY KEY (`Utente`);

--
-- AUTO_INCREMENT per le tabelle scaricate
--

--
-- AUTO_INCREMENT per la tabella `dati`
--
ALTER TABLE `dati`
  MODIFY `ID` int(11) NOT NULL AUTO_INCREMENT;

--
-- Limiti per le tabelle scaricate
--

--
-- Limiti per la tabella `dati`
--
ALTER TABLE `dati`
  ADD CONSTRAINT `dati_ibfk_1` FOREIGN KEY (`Utente`) REFERENCES `utenti` (`Utente`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `dati_ibfk_2` FOREIGN KEY (`Backup`) REFERENCES `dati` (`ID`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Limiti per la tabella `sicurezza`
--
ALTER TABLE `sicurezza`
  ADD CONSTRAINT `sicurezza_ibfk_1` FOREIGN KEY (`Utente`) REFERENCES `utenti` (`Utente`) ON DELETE CASCADE ON UPDATE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
