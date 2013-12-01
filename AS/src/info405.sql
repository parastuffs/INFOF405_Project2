-- phpMyAdmin SQL Dump
-- version 3.5.1
-- http://www.phpmyadmin.net
--
-- Client: localhost
-- Généré le: Dim 01 Décembre 2013 à 14:44
-- Version du serveur: 5.5.24-log
-- Version de PHP: 5.4.3

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Base de données: `info405`
--

-- --------------------------------------------------------

--
-- Structure de la table `asymkey`
--

CREATE TABLE IF NOT EXISTS `asymkey` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `owner` varchar(25) NOT NULL,
  `publicKey` text NOT NULL,
  `privateKey` text,
  `creationDate` int(11) NOT NULL,
  `salt` varchar(255) NOT NULL,
  `validity` tinyint(4) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=21 ;

--
-- Contenu de la table `asymkey`
--

INSERT INTO `asymkey` (`id`, `owner`, `publicKey`, `privateKey`, `creationDate`, `salt`, `validity`) VALUES
(16, 'WS1', 'LCvaWCa7twTR04sKFvv7tMvG8txG0uuYhbsBOBYux4mqA84WytCYVL1E/8a9YRIUZ9N/gPwoBrvT+gsZ3Y2pAV4G2N/IVO60AklmyzoD9eWMRN3UbxZ3VzmEDuOCLP7WibvJ4YEEoK2LfVGbW8VjiDjtQ1aeSVO+jQIDS2VJLdtuvf+TIjXqzV8RMq+FXmJJxprdoeyYXGSJTCR+qFZm6NMhpiGDMF7sFomWCH79NdQXO1c20iVYiF8l383i+mwQYmmiaJG2qzoH9D25cDlljQeJrmQxyxwxU0kzJKs/er9NOZdvGDMMpNLnY7JqKyXFjfQHAl9dvecyhJihW5GvBhtd8d9xT03VKnh5Sz2H+PlqghwxskrA8lxpUWlqsK/Q', '', 1385908419, '850c4f9c10eb919c48fa4ea6ede01f40f5df11c6d2de22029d', 0),
(17, 'WS2', 'WZ7rv3v3sfLOV+wCPEdFNBVVlg1T7o6nSS+ckmUQqW+uND7Y1TBgsRDnzMzL4H3mqRL3n/iYmYRFJLijshImHNgBxgfmHxlsGYFEGEcVZ8OYywgo+ULeJB4Fo5NheoyOGrYFou+oGUPE4MxsDN4CL6o1hrZ1Godt/o24LzBq81aT4kbtFxlNiyPNnfSwp3TX8Txigq0KYHrGOR+Lok3rn0gEqALY+KLtNOAP8yy3lDsnRk37NIftOW11MZLqIcSDon0+qwoit8xC31h1Y6p8TWPcQwExR6so351bjGOw8bRoJuMlyye2h0gygwtV5JFseNw2HWjcap8fUbPDcEp45/1Dt67d10SzN4dL4uYWW+p1DeRa1UZ3AZLaEVPiToQi', '', 1385908419, 'b65b0999920cf617ae827ff396c9aec789e5ff53ff73c4b978', 1),
(18, 'AS', 'B5J9p1GyK2JMW8154RMPNCol2LwhENaIxrmiDAuoa89GjGuuV04RwtULSayEU0kv/qQhBTWANpva/On9tojrKmboiQouG5kVFmipsjNTOCNgnokJywMxo7WEl8DG2sr+vak1Z4CqK1c4P/Npy12SIKI8w2A2GHyUjCgJP74eueGgklJgP81OclDNaT+3uuxZ6dkUKEPXh38Se5N4v9AYVEoMrQReH2AvWUVr5HvIbcnWMG+WPp7O+HflZ4tA9xhIxKPScbCBfWA/sVr3h6CzABv656p7V6PZ5Y2DYlEWYSYbNMuKG/z/Xppav0m7aTlm8amf6GublXtAaZRDfFfWmCqXQOms6oxoz6RYZPibeDH3ttxYUHAwx7XuKPv75LSE', 'Lju9LcKNJUpnSOKjB/Gdf6Zkttan9vNDELOcAHmRRwt9F1sC769hZCSmvoGqo678hB/jYjItelgaJklAaqTK6x6bdogcnc6gPWea9XzPSqFsG/wNEgqsLUSCwg4HHvBOBLpKn7br/wrUZfpg089RUG+gOjSOYo9jyXm/71pXWbXzTOnNUOG+SS+FgjuMtD6yUn6lkj0FgV9jbbgGlKFmAvtCQ6xmS1HMcs+L17b2vjkDpT9FrGclFAap7RluHyq0c8apSGGeZSQ56/Kx0sW0zKg31fLzTrLTh81H0tANS1/GUBJ05j7rGsiL++aWseHvgOXHbEkoeOHBCJ+M932TJpCXorwzCkkcbDJ/KtUdULjuZLsx65toCYd5UJNZqGZEXWENecd6am8uoHu4mgIBXeBKlgG/Bre9OJs76GilEVO+DbK6NBgecntLiSK3tCwK5bXldAtsz5391drYPeHsghTRs6PZqiN6NydWWJAemEDbufBab9K5/st77MGy4EPz7LTtEwIn0NeFPdp9uZLwrDlwVm50NeS/smVnozoQICZOGq2qFxEE6BJuzZgJ0sWd3vhtFz6HS7FoRPduGw1X2ltxSKqV9UZs3dR2mYxojSN9nrcRUD1N5jgW1EFhL2+LqZvcW4MrOxCfYJhPdxswWChFCb3ZbsdGdAtntoTVo7hrUuKnvE5G0tnma2hzKTJ22Yn+c2MzVUt/Keq/mfEXIoWKiywEUWILATLXs8t6i5gd9BpSjtxXK5h/axYVDS9HfvK3lakKsFvan4Yrv0SBgZ6WTaEDFfcWD5OmMwN05oaimZH7+s/odPdstlj9PAq5qFytAQ9gHiDM5iv6TqLXBpHVMgARcs1zbv+Vc5LqHbRUE+09vlLJedJkAnJntVeeaCSLoY/ESIZ1/HO9ATrGssTDxhdTNCFkngUh6kbSvkJ1xoHFHZv03TCuhFbCjtvTNDo55BzFwStb/6I0CNNcGGUN1wnUr8Q0KAHa1d1BD3cxOnFo9rHVVmyusKZGw+Sl6v6qIC31+I71l34cxCKHJvs25eFEkhcxdBFsNP5ONpzQGnZRf0ZpII+elXj2ws1nlx1skx/83Xcd9TaW9WxOcMMg/pndKU6DP8gbvGpOPQ9KtCjzywdy/wFumQXu1TmiHF3P1ZTkbV0JmJIjVfJAdHphJUDhc9pJJ67/BDbsgK6gusBDEcU4PZTgqERNvudPGcXSbM7KpX8FLiLhMCZ5fiDsKtg=', 1385908419, '1fa8c70bdccb37fc0441c9beeb301cf274926ca20af07c8819', 1),
(19, 'WS1', 'nsMSpemPyZmQ85Eq2lpwgHIRbNL+6hsLh3ZmRN6VQ2oexWkzf2n5WYn4vBdKKwuLrzqgIczijnMSSZvYXo5qa+X6IIsUn44EvaDVJKkL/WEhnbawCSyfDE1pG5uA0GG2UuZlGmul01ORtzsh66BuyNI9eTB1BatYpL5/hgKcRuH4X4AoXnhmh4g9+YGyxX11kZ1M4GGDyDR+yCBRS/IsvWDq+UV8Ng+/qNh2KqisyL+q31ctFt8ftaBaVFQqncPf6J/vjM5D6/U9txnoWpdb8jjtkCgMvOaM8QYagtb70vM984A0BkL9VcrW//RxILmbrpDXulZpaodcKBZqVv0SXwTYQH2WlDZmTW2JmhdM6qZbVikT21pfCMNKxh3QpZ1A', '', 1385908955, '5f12c9706334575a6b41b323d6899eed1c548b249b3d77838e', 0),
(20, 'WS1', 'BhpNn9iMTfqHGtxzWigEMfDjNnANCpKcSe6ETBCJNf2cwkNP6r4jmMfC+J28B6+ktL5foAbUT/R5C3aOOW/onqb+AVavIZMwGbHGjLszIUsNnqp4PuIogqupctA71IJe1axBjkqGS1Z9eqxqAWYK0azXBfRB+qH6kzXJ/CzeNoG+4q574I4o+R/ZoWo1sI5jM8tZ4h1NSPqsa2FPhrDfbRWy//pybEMXzsbSPlXQsP1zmNv+OXCOmyyYQOsnM0lm+1FDocIeGg/i0xtxQ5c5QXZm2OPaYpABZOZXDvIkrNU+UCisKSZ2kB7/pEyQlPWxhB8IxXNRedwkn5wmOlhYCiJ8IZc8ySjc+BG44gsY6zbJwL4Pdy3C28V+FkRN2Lbt', '', 1385908957, '39a643c04b4844dd55eecfcadba0117779b84575bc8885edd6', 1);

-- --------------------------------------------------------

--
-- Structure de la table `sessionkey`
--

CREATE TABLE IF NOT EXISTS `sessionkey` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `key` varchar(255) NOT NULL,
  `horigin` varchar(40) NOT NULL,
  `origin` varchar(255) NOT NULL,
  `destination` varchar(255) NOT NULL,
  `hdestination` varchar(40) NOT NULL,
  `salt` varchar(255) NOT NULL,
  `creationDate` int(11) NOT NULL,
  `validity` tinyint(4) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Structure de la table `user`
--

CREATE TABLE IF NOT EXISTS `user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `husername` varchar(40) NOT NULL,
  `salt` varchar(255) NOT NULL,
  `WS1` varchar(255) NOT NULL,
  `WS2` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
