#!/bin/bash

# Model list
models=(
    # "gpt-4o-mini-2024-07-18"
     "deepseek-chat"
#    "gpt-3.5-turbo-0125"
    # "Mixtral-8x7B-Instruct-v0.1"
    # "gpt-4o-2024-08-06"
    # "o1-mini-2024-09-12"
    
)

# Parameter settings
method="v"
levenshtein_num=0.5
max_retries=1

# Function definition: run model
run_model() {
    model=$1
    language=$2
    script=$3
    time=$4  
    attempt=1
    success=false


    while [ $attempt -le $max_retries ]; do
        echo "Running model: $model (Language: $language, Attempt $attempt/$max_retries)"
        
        # Run Python script
        python "$script" --method "$method" --model "$model" --language "$language" --time "$time" --levenshtein_num "$levenshtein_num"
        # Check exit status
        if [ $? -eq 0 ]; then
            echo "Model $model ran successfully!"
            success=true
            break
        else
            echo "Model $model failed, retrying..."
        fi
        
        attempt=$((attempt + 1))
    done

    if [ "$success" = false ]; then
        echo "Model $model still failed after $max_retries attempts."
    fi
}


for model in "${models[@]}"; do
    # run_model "$model" "C" "main_with_diff.py" "01" &
    run_model "$model" "Java" "main.py" "01" &
done

wait
echo "All models completed."

