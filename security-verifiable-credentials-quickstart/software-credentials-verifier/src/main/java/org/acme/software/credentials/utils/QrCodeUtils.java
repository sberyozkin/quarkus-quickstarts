package org.acme.software.credentials.utils;

import java.io.ByteArrayOutputStream;
import java.util.Base64;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;

public final class QrCodeUtils {
    private QrCodeUtils() {

    }

    public static String generateQrCode(String data) {

        try {

            BitMatrix matrix = new MultiFormatWriter().encode(data, BarcodeFormat.QR_CODE, 200, 200);

            ByteArrayOutputStream stream = new ByteArrayOutputStream();

            MatrixToImageWriter.writeToStream(matrix, "png", stream);

            return Base64.getEncoder().encodeToString(stream.toByteArray());
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }

    }
}
