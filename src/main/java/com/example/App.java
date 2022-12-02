package com.example;

/**
 * Hello world!
 */
public final class App {
    private App() {
    }

    /**
     * Says hello to the world.
     * @param args The arguments of the program.
     */
    public static void main(String[] args) {
        System.out.println("Hello World!");
        Idbridge idbridge = new Idbridge();
        String saml = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiCiAgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgVmVyc2lvbj0iMi4wIj4KICA8c2FtbDpBc3NlcnRpb24geG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgSUQ9ImpHUWtyNEEwcDRPcGNOM1NkWGZielJWRXRRZCIgSXNzdWVJbnN0YW50PSIyMDIyLTExLTI5VDIwOjM5OjEyLjgwNVoiIFZlcnNpb249IjIuMCI+CiAgICA8c2FtbDpJc3N1ZXI+aHR0cHM6Ly9waW5nZmVkZXJhdGUucGF0LnRkLmNvbTo5MDMxPC9zYW1sOklzc3Vlcj4KICAgIDxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPgogICAgICA8ZHM6U2lnbmVkSW5mbz4KICAgICAgICA8ZHM6Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIgLz4KICAgICAgICA8ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxkc2lnLW1vcmUjcnNhLXNoYTI1NiIgLz4KICAgICAgICA8ZHM6UmVmZXJlbmNlIFVSST0iI2pHUWtyNEEwcDRPcGNOM1NkWGZielJWRXRRZCI+CiAgICAgICAgICA8ZHM6VHJhbnNmb3Jtcz4KICAgICAgICAgICAgPGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIiAvPgogICAgICAgICAgICA8ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIiAvPgogICAgICAgICAgPC9kczpUcmFuc2Zvcm1zPgogICAgICAgICAgPGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIgLz4KICAgICAgICAgIDxkczpEaWdlc3RWYWx1ZT4yZ0wvN1FFV0pwWUZVbWpvOC9QVHI3NHorTzRmOThMQzNzRXNkQnFiTGhJPTwvZHM6RGlnZXN0VmFsdWU+CiAgICAgICAgPC9kczpSZWZlcmVuY2U+CiAgICAgIDwvZHM6U2lnbmVkSW5mbz4KICAgICAgPGRzOlNpZ25hdHVyZVZhbHVlPklYODJtZ2t2aEhGU2lWK0xpSm9ud1h0RXdoZEN4bnFYTkJheWMyK3Y3ZG1sb1NKbDlIRHo5bWM5N29NRCtnaTc1eDZkQitXVFNwUWdDTlRYUFFoTzdQTjZXQlFPV2FkMVpQUkM1WGoxcEErUjN2eW9mbnVjREtSNG1JMFlSVmZxa0dRWmFZU3FkQ2phVWEvNmtMYnRhRXp0eUpNQ3JPd0lhVnVRTXBQZHdxVnBPUkt3NGRMK25CSGJCb3lUeUNHUjRTMmFGVDJNQlRsM2pFN3pmNm85MVRneDM0RlNrT2JveWhXczErc3RvQm1sOTBIZEFPRUYrTTRibytGdE9IYTU0MkxxRmlOOE5KUFFSd2xSZDJpWTdEd2gxUFM4SkQ5YUxydHJhVUZoMnV5bDZOSGRDMk9ad0U0T0VkdTV5TGJsUC9iSlZaR004QXpncmtqWERTNEJOQT09PC9kczpTaWduYXR1cmVWYWx1ZT4KICAgICAgPGRzOktleUluZm8+CiAgICAgICAgPGRzOlg1MDlEYXRhPgogICAgICAgICAgPGRzOlg1MDlDZXJ0aWZpY2F0ZT5NSUlIa2pDQ0JYcWdBd0lCQWdJVFN3QURVYjNvV0VKUGdZYVNvd0FCQUFOUnZUQU5CZ2txaGtpRzl3MEJBUXNGQURCS01STXdFUVlLQ1pJbWlaUHlMR1FCR1JZRFkyOXRNUmN3RlFZS0NaSW1pWlB5TEdRQkdSWUhjQzEwWkdKbVp6RWFNQmdHQTFVRUF3d1JWRVJKYzNOMWFXNW5NREZEUVY5UVlYUXdIaGNOTWpFeE1qSTVNVFF6TXpJeVdoY05Nak14TWpJNU1UUXpNekl5V2pDQmt6RUxNQWtHQTFVRUJoTUNRMEV4RURBT0JnTlZCQWdUQjA5dWRHRnlhVzh4RURBT0JnTlZCQWNUQjFSdmNtOXVkRzh4SWpBZ0JnTlZCQW9UR1ZSb1pTQlViM0p2Ym5SdkxVUnZiV2x1YVc5dUlFSmhibXN4RURBT0JnTlZCQXNUQjJWQ1UxTlVTVk14S2pBb0JnTlZCQU1USVhCaGRDNWpabVZrWkdsbmFYUmhiSE5wWjI1cGJtZGpaWEowTG5Sa0xtTnZiVENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFLeVVDTjdFVFhrNlh1b1lIOTBnVEViYjJuL3A3SzlPUjI0UmZsM3NGZE9paVdIZDB2SDloYjJzeEtjam5yM3gzeDJEb3dTK3lySmhXeUU3S3ZLdmFYZ2hZclJQeTArVlJNc1BWUjhIOWJoOGZmQXY5S1M4bmFJcGFWQ2Y3MmE5YmJkVnhBeWlYeGN2R0hhNEUvem9QSDhucTVtM0RCME9wT3BkWjREdm1YZFNCaTlwY05qSWcxRlhyaEpjZG9TMmg2N0ZDeUt2OFVqL3cvUTMzVFpYTWp4YURqK3JIYXRyL0dGbXBxaTc5Mlo0b1M4VkdKcElsTXM2RURsN2Q3VDNvT21sNWRZdzhaNnhSU01uNHB3cDVRV3UvZHgxSFZXZ3V4SFp0bWZrOCtYVXE4UGdtWTduN3dUK2FOSXZGOG5ST2ErMDRsMlNwcUZxeFJ4Vi9DZ3lLZVVDQXdFQUFhT0NBeVV3Z2dNaE1Dd0dBMVVkRVFRbE1DT0NJWEJoZEM1alptVmtaR2xuYVhSaGJITnBaMjVwYm1kalpYSjBMblJrTG1OdmJUQWRCZ05WSFE0RUZnUVVmQ0swQWJBRml3MVkwRFFkaW9VVEdMV29jSjB3SHdZRFZSMGpCQmd3Rm9BVVQyaGp6Z2ppMEljWmhXbzZWR0ptU0xlc1J4RXdnZmNHQTFVZEh3U0I3ekNCN0RDQjZhQ0I1cUNCNDRZeWFIUjBjRG92TDNCcmFTMWpaSEF1ZEdSaVlXNXJMbU5oTDNCcmFTOVVSRWx6YzNWcGJtY3dNVU5CWDFCaGRDNWpjbXlHZ2F4c1pHRndPaTh2TDBOT1BWUkVTWE56ZFdsdVp6QXhRMEZmVUdGMExFTk9QVU5FVUN4RFRqMVFkV0pzYVdNbE1qQkxaWGtsTWpCVFpYSjJhV05sY3l4RFRqMVRaWEoyYVdObGN5eERUajFEYjI1bWFXZDFjbUYwYVc5dUxFUkRQWEF0Wm1rc1JFTTliRzlqWVd3L1kyVnlkR2xtYVdOaGRHVlNaWFp2WTJGMGFXOXVUR2x6ZEQ5aVlYTmxQMjlpYW1WamRFTnNZWE56UFdOU1RFUnBjM1J5YVdKMWRHbHZibEJ2YVc1ME1JSUJJZ1lJS3dZQkJRVUhBUUVFZ2dFVU1JSUJFRENCcndZSUt3WUJCUVVITUFLR2dhSnNaR0Z3T2k4dkwwTk9QVlJFU1hOemRXbHVaekF4UTBGZlVHRjBMRU5PUFVGSlFTeERUajFRZFdKc2FXTWxNakJMWlhrbE1qQlRaWEoyYVdObGN5eERUajFUWlhKMmFXTmxjeXhEVGoxRGIyNW1hV2QxY21GMGFXOXVMRVJEUFhBdFpta3NSRU05Ykc5allXdy9ZMEZEWlhKMGFXWnBZMkYwWlQ5aVlYTmxQMjlpYW1WamRFTnNZWE56UFdObGNuUnBabWxqWVhScGIyNUJkWFJvYjNKcGRIa3dYQVlJS3dZQkJRVUhNQUtHVUdoMGRIQTZMeTl3YTJrdFkyUndMblJrWW1GdWF5NWpZUzl3YTJrdlExSkJRVUZXUWtNeE1VMVRRMEV1Y0MxMFpHSm1aeTVqYjIxZlZFUkpjM04xYVc1bk1ERkRRVjlRWVhRb01Ta3VZM0owTUFzR0ExVWREd1FFQXdJRm9EQThCZ2tyQmdFRUFZSTNGUWNFTHpBdEJpVXJCZ0VFQVlJM0ZRaUMzZDkvaGYzaFFZWGRuU0NFaGFCTnhONHpYb1dUdDAyRGx2NCtBZ0ZrQWdFS01CMEdBMVVkSlFRV01CUUdDQ3NHQVFVRkJ3TUNCZ2dyQmdFRkJRY0RBVEFuQmdrckJnRUVBWUkzRlFvRUdqQVlNQW9HQ0NzR0FRVUZCd01DTUFvR0NDc0dBUVVGQndNQk1BMEdDU3FHU0liM0RRRUJDd1VBQTRJQ0FRQ3krWlZGWUdxWmhBdnVNWE5LRjE3a0pqNzB1VnUyZ0NxVjBGaHdUN0RVNFJXc1c4VkVVWVE0QnRQcDRLSjVSbEJnd0QzankrNXMvWGRnY1NFa2dTME8xOTAxaGdvcVMwaXo1TDBvdTJ5dFhyNk1ESnFCWnZuU2RPRG5hWVZxaWEwd2R6eVNVaVFQSS9Vd0lhdHRsNUMvZ3phcVByY05VSlVXNXhWRU8rWks4Smoxbmh4azRnYXJYYS92dlYrS0ovbjZxT0tVVnhvR2hKUktzN0Exd1ZPQW96TG5MSE5VWU5hSjVBNWVzQ2QwVHpTMmdITm9uQ3QzL1RjQllCTFU3Zk1ldGVJRXpGUktMek9CNDYvTDMyRWc2ekxPU2sxQ0lOMHl0blV6dUZ6WDJScmRiRVlqTFk0QzZGVEdMaG84ZVNYaVk0UDIzRGlwTmpDSGJaSWJQb2crR3QzZDV4a2RkVHQxNjFaYmFwZUF2L1EwaGtTNzkzb1NkeGk3Ylp5c1AwQkM1bStIZ0J2SUY2YzVISDYyeGtSTWlKTWk5c0FGRThQUVFFRDYyY0NyYjU4SUpWYVhJa1pRSklUbGlHVWxUNllaeUd0WFZMNTVGRGtzWnJ6ZzdWdXBxYllteGxpbHdSSTZKcDViYUgyY2g2K0VpaUlaYU5FUDR5SFNlYWFuQUR0KzhOT0tnSDU3dU54cFEvREJEOXBzS2dPQ2Fna0gxeVhkSlBlN2hDOFpBejl2cU5ab25jOGQ4TXY5NUdEbXpwSEJ6cEtucWVTU0pnZFd2UHBVM2tHQXBxeFMvTUJCRTgzczBaOUJSWU95WGpFYS93R09zdHh4VjEvZEQrL2V0NnFMbnhmRVBWNEVacTFvNld3aUNhNmhOUFowODVUNnhJNmVLUW5QV05XYTJBPT08L2RzOlg1MDlDZXJ0aWZpY2F0ZT4KICAgICAgICA8L2RzOlg1MDlEYXRhPgogICAgICA8L2RzOktleUluZm8+CiAgICA8L2RzOlNpZ25hdHVyZT4KICAgIDxzYW1sOlN1YmplY3Q+CiAgICAgIDxzYW1sOk5hbWVJRCBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjEuMTpuYW1laWQtZm9ybWF0OnVuc3BlY2lmaWVkIj44NWRjNTY1NS0yN2M1LTRlMGEtYTMxYS03ZjE1OGFkNzI3Mzc8L3NhbWw6TmFtZUlEPgogICAgICA8c2FtbDpTdWJqZWN0Q29uZmlybWF0aW9uIE1ldGhvZD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmNtOmJlYXJlciIgLz4KICAgIDwvc2FtbDpTdWJqZWN0PgogICAgPHNhbWw6Q29uZGl0aW9ucyBOb3RCZWZvcmU9IjIwMjItMTEtMjlUMjA6MzQ6MTIuODA1WiIgTm90T25PckFmdGVyPSIyMDIyLTExLTI5VDIxOjA5OjEyLjgwNVoiPgogICAgICA8c2FtbDpBdWRpZW5jZVJlc3RyaWN0aW9uPgogICAgICAgIDxzYW1sOkF1ZGllbmNlPmV3YXN5bmMtd3Mtc3RzLXBhdDwvc2FtbDpBdWRpZW5jZT4KICAgICAgPC9zYW1sOkF1ZGllbmNlUmVzdHJpY3Rpb24+CiAgICA8L3NhbWw6Q29uZGl0aW9ucz4KICAgIDxzYW1sOkF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0iMjAyMi0xMS0yOVQyMDozOToxMi44MDVaIiBTZXNzaW9uSW5kZXg9ImpHUWtyNEEwcDRPcGNOM1NkWGZielJWRXRRZCI+CiAgICAgIDxzYW1sOkF1dGhuQ29udGV4dD4KICAgICAgICA8c2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3Nlczp1bnNwZWNpZmllZDwvc2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj4KICAgICAgPC9zYW1sOkF1dGhuQ29udGV4dD4KICAgIDwvc2FtbDpBdXRoblN0YXRlbWVudD4KICAgIDxzYW1sOkF0dHJpYnV0ZVN0YXRlbWVudD4KICAgICAgPHNhbWw6QXR0cmlidXRlIE5hbWU9ImlkZW50aWZpZXIiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiPgogICAgICAgIDxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIKICAgICAgICAgIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPkMwUVhUWUFCN1g3SERKVkQ1RUdWR0pOVUs8L3NhbWw6QXR0cmlidXRlVmFsdWU+CiAgICAgIDwvc2FtbDpBdHRyaWJ1dGU+CiAgICAgIDxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJnaXZlbk5hbWUiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6YmFzaWMiPgogICAgICAgIDxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIKICAgICAgICAgIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPllMWTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT4KICAgICAgPC9zYW1sOkF0dHJpYnV0ZT4KICAgIDwvc2FtbDpBdHRyaWJ1dGVTdGF0ZW1lbnQ+CiAgPC9zYW1sOkFzc2VydGlvbj4KPC9zYW1scDpSZXNwb25zZT4=";
        idbridge.setSaml(saml);
        idbridge.start();
    }
}
